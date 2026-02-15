# vdg

This helm chart is just using a subchart of our standardized deployment helm charts

## Introduction

This chart bootstraps a highly available deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.10+ with Beta APIs enabled
- The kubectl binary
- The helm binary
- Helm diff plugin installed

## Installing the Chart

To install the chart...

```bash
# dev
export SERVICE_NAME="vdg"
export CI_ENVIRONMENT_SLUG="dev"
export K8S_NAMESPACE=$CI_ENVIRONMENT_SLUG
export HELM_CHART=$SERVICE_NAME
export CURRENT_HELM_CHART=$SERVICE_NAME
export HELM_IMG_TAG="dev-2f3887c8e5c76f295ffebc2e9973156f499c2f36"

# Go into our deployment folder
cd deployment
# Update our helm subchart...
helm dependencies update $SERVICE_NAME/
# View the diff of what you want to do
helm diff upgrade --namespace $K8S_NAMESPACE --allow-unreleased $CURRENT_HELM_CHART $HELM_CHART     -f $CURRENT_HELM_CHART/values.yaml     -f $CURRENT_HELM_CHART/values-${CI_ENVIRONMENT_SLUG}.yaml     --set global.image.tag="$HELM_IMG_TAG"
# Actually do it...
helm upgrade --namespace $K8S_NAMESPACE --install $CURRENT_HELM_CHART $HELM_CHART     -f $CURRENT_HELM_CHART/values.yaml     -f $CURRENT_HELM_CHART/values-${CI_ENVIRONMENT_SLUG}.yaml  --set global.image.tag="$HELM_IMG_TAG"
```

## Configuration

For configuration options possible, please see our [helm-charts](#todo) repository


## Misc notes

```
DNS Records for migrating to Kubernetes...
K8S = k8s-940102565.us-west-2.elb.amazonaws.com.
OLD DEV = xatp-Publi-IKH95SQRTKV2-743523145.us-west-2.elb.amazonaws.com
OLD DEMO = xatp-publi-tk7lq35uwxtd-1439125255.us-west-2.elb.amazonaws.com.
OLD PROD = xatp-publi-x7pqz6jjypmv-1508446734.us-west-2.elb.amazonaws.com.
```
