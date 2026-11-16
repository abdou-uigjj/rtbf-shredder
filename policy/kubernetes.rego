package main

import future.keywords.in

# rtbf-shredder policy pack - the rules the erasure workload must live
# by. the shredder destroys personal data; it runs with the least
# privileges kubernetes allows and we prove that here, on every push.

deny[msg] {
  input.spec.template.spec.containers[_].securityContext.privileged == true
  msg := "privileged containers are never allowed"
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %s must set allowPrivilegeEscalation: false", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %s must run with a read-only root filesystem", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  caps := object.get(c.securityContext, "capabilities", {})
  drops := object.get(caps, "drop", [])
  not "ALL" in drops
  msg := sprintf("container %s must drop ALL linux capabilities", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  object.get(c.securityContext, "runAsUser", 0) == 0
  msg := sprintf("container %s must not run as uid 0", [c.name])
}

deny[msg] {
  spec := input.spec.template.spec
  not object.get(spec, "runAsNonRoot", false) == true
  msg := "pod must set runAsNonRoot: true"
}

deny[msg] {
  spec := input.spec.template.spec
  sc := object.get(spec, "securityContext", {})
  sp := object.get(sc, "seccompProfile", {})
  object.get(sp, "type", "") != "RuntimeDefault"
  msg := "pod must set seccompProfile RuntimeDefault"
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  not object.get(c, "resources", {}).requests
  msg := sprintf("container %s must declare resource requests", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  not object.get(c, "resources", {}).limits
  msg := sprintf("container %s must declare resource limits", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("container %s must pin its image tag (no :latest)", [c.name])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  not regex.match("^[^:]+:[vV][0-9]", c.image)
  msg := sprintf("container %s image %s must use a version tag", [c.name, c.image])
}

deny[msg] {
  c := input.spec.template.spec.containers[_]
  object.get(c, "imagePullPolicy", "") == ""
  msg := sprintf("container %s must set imagePullPolicy", [c.name])
}

deny[msg] {
  v := input.spec.template.spec.volumes[_]
  object.get(v, "hostPath", null) != null
  msg := sprintf("hostPath volume %s is forbidden - the vault is a pvc", [v.name])
}

deny[msg] {
  input.spec.template.spec.volumes[_].emptyDir.medium != "Memory"
  msg := "emptyDir scratch space must be tmpfs (medium: Memory)"
}

deny[msg] {
  input.spec.template.spec.automountServiceAccountToken != false
  msg := "the shredder never talks to the kubernetes api - automountServiceAccountToken must be false"
}

deny[msg] {
  input.metadata.namespace == "default"
  msg := "workloads must not live in the default namespace"
}

deny[msg] {
  kinds := ["CronJob", "Deployment", "StatefulSet", "DaemonSet"]
  input.kind in kinds
  not input.metadata.labels.app
  msg := "every workload must carry an app label"
}

deny[msg] {
  input.kind == "CronJob"
  not input.spec.jobTemplate.spec.template.metadata.labels.app
  msg := "cronjob pod template must carry an app label"
}

deny[msg] {
  input.kind == "CronJob"
  not input.spec.schedule
  msg := "cronjob must declare its schedule"
}

deny[msg] {
  input.kind == "CronJob"
  regex.match(`\* \* \* \*`, input.spec.schedule)
  msg := "cronjob must not run every minute - erasure is a deliberate act"
}

deny[msg] {
  input.kind == "Namespace"
  not input.metadata.labels["pod-security.kubernetes.io/enforce"]
  msg := "namespace must enforce pod security standards"
}

deny[msg] {
  input.kind == "PersistentVolumeClaim"
  object.get(input.spec.resources.requests, "storage", "") == ""
  msg := "pvc must request storage"
}

deny[msg] {
  input.kind == "Secret"
  msg := "secrets do not belong in manifests - inject keys from kms at runtime"
}

deny[msg] {
  input.kind == "NetworkPolicy"
  input.spec.podSelector == {}
  count(object.get(input.spec, "ingress", [])) == 0
  count(object.get(input.spec, "egress", [])) == 0
  types := object.get(input.spec, "policyTypes", [])
  not "Ingress" in types
  msg := "default-deny must cover both ingress and egress"
}

deny[msg] {
  input.kind == "Deployment"
  not object.get(input.spec, "replicas", 1) >= 1
  msg := "deployment must declare a positive replica count"
}
