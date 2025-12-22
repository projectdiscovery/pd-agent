package supervisor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/projectdiscovery/gologger"
)

// KubernetesProvider implements the Provider interface for Kubernetes deployments
type KubernetesProvider struct {
	clientset kubernetes.Interface
	namespace string
}

// NewKubernetesProvider creates a new Kubernetes provider
func NewKubernetesProvider() (*KubernetesProvider, error) {
	var config *rest.Config
	var err error

	// Try in-cluster config first (when running inside Kubernetes)
	config, err = rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig file
		var kubeconfig string
		if kubeconfigPath := os.Getenv("KUBECONFIG"); kubeconfigPath != "" {
			kubeconfig = kubeconfigPath
		} else {
			home := homedir.HomeDir()
			if home != "" {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}

		if kubeconfig != "" {
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get Kubernetes config: %w", err)
		}
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = clientset.CoreV1().Namespaces().Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes API: %w", err)
	}

	// Use default namespace (local endpoint only)
	return &KubernetesProvider{
		clientset: clientset,
		namespace: "pd-agent",
	}, nil
}

// Name returns the provider name
func (k *KubernetesProvider) Name() string {
	return "kubernetes"
}

// IsAvailable checks if Kubernetes is available
func (k *KubernetesProvider) IsAvailable(ctx context.Context) bool {
	if k.clientset == nil {
		return false
	}

	// Test API server connectivity
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := k.clientset.CoreV1().Namespaces().Get(ctx, "default", metav1.GetOptions{})
	return err == nil
}

// PullImage is a no-op for Kubernetes (kubelet handles image pulling)
func (k *KubernetesProvider) PullImage(ctx context.Context, image string) error {
	// Kubernetes handles image pulling automatically via kubelet
	// No action needed here
	return nil
}

// Deploy deploys a Kubernetes Deployment
func (k *KubernetesProvider) Deploy(ctx context.Context, config *DeploymentConfig) (string, error) {
	// Convert DeploymentConfig to Kubernetes Deployment
	deployment, secret, err := k.deploymentConfigToKubernetes(config)
	if err != nil {
		return "", fmt.Errorf("failed to convert config: %w", err)
	}

	// Create or update Secret if needed
	if secret != nil {
		_, err = k.clientset.CoreV1().Secrets(k.namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// Create secret
			_, err = k.clientset.CoreV1().Secrets(k.namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return "", fmt.Errorf("failed to create secret: %w", err)
			}
			gologger.Info().Msgf("Created secret: %s", secret.Name)
		} else if err != nil {
			return "", fmt.Errorf("failed to check secret: %w", err)
		}
		// Secret exists, use it
	}

	// Check if Deployment already exists
	existing, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
	if err == nil {
		// Deployment exists, update it
		deployment.ResourceVersion = existing.ResourceVersion
		_, err = k.clientset.AppsV1().Deployments(k.namespace).Update(ctx, deployment, metav1.UpdateOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to update deployment: %w", err)
		}
		gologger.Info().Msgf("Updated deployment: %s", deployment.Name)
	} else if errors.IsNotFound(err) {
		// Create new Deployment
		_, err = k.clientset.AppsV1().Deployments(k.namespace).Create(ctx, deployment, metav1.CreateOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to create deployment: %w", err)
		}
		gologger.Info().Msgf("Created deployment: %s", deployment.Name)
	} else {
		return "", fmt.Errorf("failed to check deployment: %w", err)
	}

	// Wait for Deployment to be ready
	err = k.waitForDeploymentReady(ctx, deployment.Name, 60*time.Second)
	if err != nil {
		return "", fmt.Errorf("deployment not ready: %w", err)
	}

	return deployment.Name, nil
}

// Stop stops a Deployment by scaling it to 0 replicas
func (k *KubernetesProvider) Stop(ctx context.Context, deploymentID string, timeout *int) error {
	deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, deploymentID, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	// Scale to 0
	replicas := int32(0)
	deployment.Spec.Replicas = &replicas
	_, err = k.clientset.AppsV1().Deployments(k.namespace).Update(ctx, deployment, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to scale deployment to 0: %w", err)
	}

	// Wait for Pods to terminate
	waitTimeout := 30 * time.Second
	if timeout != nil {
		waitTimeout = time.Duration(*timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()

	err = k.waitForDeploymentReplicas(ctx, deploymentID, 0)
	if err != nil {
		return fmt.Errorf("failed to wait for pods to terminate: %w", err)
	}

	gologger.Info().Msgf("Stopped deployment: %s", deploymentID)
	return nil
}

// Remove removes a Deployment
func (k *KubernetesProvider) Remove(ctx context.Context, deploymentID string) error {
	err := k.clientset.AppsV1().Deployments(k.namespace).Delete(ctx, deploymentID, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete deployment: %w", err)
	}

	// Also delete associated Secret if it exists
	secretName := "pd-agent-secret"
	err = k.clientset.CoreV1().Secrets(k.namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		// Log but don't fail - secret might be managed externally
		gologger.Warning().Msgf("Failed to delete secret %s: %v", secretName, err)
	}

	gologger.Info().Msgf("Removed deployment: %s", deploymentID)
	return nil
}

// Start starts a Deployment by scaling it to 1 replica
func (k *KubernetesProvider) Start(ctx context.Context, deploymentID string) error {
	deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, deploymentID, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	// Scale to 1
	replicas := int32(1)
	deployment.Spec.Replicas = &replicas
	_, err = k.clientset.AppsV1().Deployments(k.namespace).Update(ctx, deployment, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to scale deployment to 1: %w", err)
	}

	// Wait for Deployment to be ready
	err = k.waitForDeploymentReady(ctx, deploymentID, 60*time.Second)
	if err != nil {
		return fmt.Errorf("deployment not ready: %w", err)
	}

	gologger.Info().Msgf("Started deployment: %s", deploymentID)
	return nil
}

// Inspect inspects a Deployment and returns its status
func (k *KubernetesProvider) Inspect(ctx context.Context, deploymentID string) (*DeploymentInfo, error) {
	deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, deploymentID, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Get Pod status
	pods, err := k.clientset.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set(deployment.Spec.Selector.MatchLabels).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	var podStatus string
	var running bool
	var exitCode int
	var imageID string

	if len(pods.Items) > 0 {
		pod := pods.Items[0]
		podStatus = string(pod.Status.Phase)
		running = pod.Status.Phase == corev1.PodRunning

		// Get container status
		if len(pod.Status.ContainerStatuses) > 0 {
			containerStatus := pod.Status.ContainerStatuses[0]
			if containerStatus.State.Terminated != nil {
				exitCode = int(containerStatus.State.Terminated.ExitCode)
			}
			// Get image ID (digest)
			if containerStatus.ImageID != "" {
				imageID = containerStatus.ImageID
			}
		}

		// Fallback to image from spec if imageID not available
		if imageID == "" && len(pod.Spec.Containers) > 0 {
			imageID = pod.Spec.Containers[0].Image
		}
	} else {
		// No pods, check deployment status
		if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 0 {
			podStatus = "ScaledDown"
			running = false
		} else {
			podStatus = "Pending"
			running = false
		}
		// Use image from deployment spec
		if len(deployment.Spec.Template.Spec.Containers) > 0 {
			imageID = deployment.Spec.Template.Spec.Containers[0].Image
		}
	}

	return &DeploymentInfo{
		ID:       deployment.Name,
		Status:   podStatus,
		Running:  running,
		ExitCode: exitCode,
		ImageID:  imageID,
	}, nil
}

// GetLogs retrieves logs from a Pod
func (k *KubernetesProvider) GetLogs(ctx context.Context, deploymentID string, follow bool) (io.ReadCloser, error) {
	deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, deploymentID, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Get Pods for this deployment
	pods, err := k.clientset.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set(deployment.Spec.Selector.MatchLabels).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found for deployment %s", deploymentID)
	}

	// Use the first pod
	pod := pods.Items[0]
	containerName := "pd-agent"
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}

	// Get logs
	req := k.clientset.CoreV1().Pods(k.namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    follow,
		TailLines: int64Ptr(100),
	})

	return req.Stream(ctx)
}

// FindByName finds a Deployment by name
func (k *KubernetesProvider) FindByName(ctx context.Context, name string) (string, error) {
	_, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("deployment not found: %w", err)
	}
	return name, nil
}

// Exists checks if a Deployment exists
func (k *KubernetesProvider) Exists(ctx context.Context, name string) bool {
	_, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// GetImageID gets the current image ID for a given image reference
func (k *KubernetesProvider) GetImageID(ctx context.Context, imageRef string) (string, error) {
	// List all deployments in namespace
	deployments, err := k.clientset.AppsV1().Deployments(k.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list deployments: %w", err)
	}

	// Find deployment with matching image
	for _, deployment := range deployments.Items {
		if len(deployment.Spec.Template.Spec.Containers) > 0 {
			containerImage := deployment.Spec.Template.Spec.Containers[0].Image
			// Match image reference (could be with or without tag)
			if containerImage == imageRef || strings.HasPrefix(containerImage, imageRef+":") {
				// Try to get actual image ID from Pod
				pods, err := k.clientset.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
					LabelSelector: labels.Set(deployment.Spec.Selector.MatchLabels).String(),
				})
				if err == nil && len(pods.Items) > 0 {
					pod := pods.Items[0]
					if len(pod.Status.ContainerStatuses) > 0 {
						if pod.Status.ContainerStatuses[0].ImageID != "" {
							return pod.Status.ContainerStatuses[0].ImageID, nil
						}
					}
				}
				// Fallback to image reference
				return containerImage, nil
			}
		}
	}

	// If no deployment found, return the image reference itself
	// (image might not be deployed yet)
	return imageRef, nil
}

// FindByPrefix finds all Deployments with names starting with the given prefix
func (k *KubernetesProvider) FindByPrefix(ctx context.Context, prefix string) ([]string, error) {
	deployments, err := k.clientset.AppsV1().Deployments(k.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	var matchingDeployments []string
	for _, deployment := range deployments.Items {
		if strings.HasPrefix(deployment.Name, prefix) {
			matchingDeployments = append(matchingDeployments, deployment.Name)
		}
	}

	return matchingDeployments, nil
}

// Helper functions

// deploymentConfigToKubernetes converts DeploymentConfig to Kubernetes Deployment and Secret
func (k *KubernetesProvider) deploymentConfigToKubernetes(config *DeploymentConfig) (*appsv1.Deployment, *corev1.Secret, error) {
	// Parse environment variables and extract secrets
	envVars := []corev1.EnvVar{}
	secretData := make(map[string][]byte)
	hasSecret := false

	for _, env := range config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		// Store PDCP_API_KEY and PDCP_TEAM_ID in Secret
		if key == "PDCP_API_KEY" || key == "PDCP_TEAM_ID" {
			secretData[key] = []byte(value)
			hasSecret = true
			envVars = append(envVars, corev1.EnvVar{
				Name: key,
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "pd-agent-secret",
						},
						Key: key,
					},
				},
			})
		} else {
			envVars = append(envVars, corev1.EnvVar{
				Name:  key,
				Value: value,
			})
		}
	}

	// Create Secret if needed
	var secret *corev1.Secret
	if hasSecret {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pd-agent-secret",
				Namespace: k.namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: secretData,
		}
	}

	// Parse volumes
	volumeMounts := []corev1.VolumeMount{}
	volumes := []corev1.Volume{}
	for i, vol := range config.Volumes {
		parts := strings.Split(vol, ":")
		if len(parts) == 2 {
			volumeName := fmt.Sprintf("volume-%d", i)
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      volumeName,
				MountPath: parts[1],
			})
			volumes = append(volumes, corev1.Volume{
				Name: volumeName,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: parts[0],
					},
				},
			})
		}
	}

	// Build security context with capabilities
	securityContext := &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{},
		},
	}
	for _, cap := range config.CapAdd {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, corev1.Capability(cap))
	}

	// Create Deployment
	replicas := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Name,
			Namespace: k.namespace,
			Labels: map[string]string{
				"app":        "pd-agent",
				"managed-by": "pd-agent-supervisor",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "pd-agent",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "pd-agent",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "pd-agent",
							Image:           config.Image,
							ImagePullPolicy: corev1.PullAlways,
							Command:         config.Cmd,
							Env:             envVars,
							VolumeMounts:    volumeMounts,
							SecurityContext: securityContext,
						},
					},
					Volumes:      volumes,
					HostNetwork:  config.NetworkMode == "host",
					RestartPolicy: corev1.RestartPolicyNever, // Supervisor manages restarts
				},
			},
		},
	}

	return deployment, secret, nil
}

// waitForDeploymentReady waits for a Deployment to be ready
func (k *KubernetesProvider) waitForDeploymentReady(ctx context.Context, name string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Check if deployment is ready
		if deployment.Status.ReadyReplicas >= 1 && deployment.Status.Replicas == 1 {
			return true, nil
		}

		return false, nil
	})
}

// waitForDeploymentReplicas waits for a Deployment to reach the desired number of replicas
func (k *KubernetesProvider) waitForDeploymentReplicas(ctx context.Context, name string, desiredReplicas int32) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		deployment, err := k.clientset.AppsV1().Deployments(k.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if deployment.Status.Replicas == desiredReplicas {
			return true, nil
		}

		return false, nil
	})
}

// int64Ptr returns a pointer to an int64
func int64Ptr(i int64) *int64 {
	return &i
}

