# AegisX9 developer workspace: one pod per developer, running the signed devcontainer
# image by digest, with a persistent home volume. Every model call leaves the workspace
# through the AegisX9 gateway (ANTHROPIC_BASE_URL); no provider key exists here.

data "coder_workspace" "me" {}

data "coder_workspace_owner" "me" {}

# --- Per-workspace choices (shown in the Coder UI when a workspace is created) ---------

data "coder_parameter" "cpu" {
  name         = "cpu"
  display_name = "CPU"
  description  = "CPU cores (request = limit; the namespace quota is shared by the team)."
  type         = "number"
  default      = "2"
  mutable      = true
  order        = 1
  option {
    name  = "2 cores"
    value = "2"
  }
  option {
    name  = "4 cores"
    value = "4"
  }
}

data "coder_parameter" "memory" {
  name         = "memory"
  display_name = "Memory"
  description  = "Memory in GiB (request = limit)."
  type         = "number"
  default      = "4"
  mutable      = true
  order        = 2
  option {
    name  = "4 GiB"
    value = "4"
  }
  option {
    name  = "8 GiB"
    value = "8"
  }
}

data "coder_parameter" "team" {
  name         = "team"
  display_name = "Team"
  description  = "Team that owns this workspace (label `team`, used for cost and access reporting)."
  type         = "string"
  default      = "platform"
  mutable      = false
  order        = 3
  validation {
    regex = "^[a-z][a-z0-9-]{1,30}$"
    error = "team must be a lowercase DNS-style label (2-31 characters)."
  }
}

data "coder_parameter" "code_server" {
  name         = "code_server"
  display_name = "Browser VS Code (code-server)"
  description  = "Expose code-server as a Coder app. Off by default; the supported editors are VS Code Remote-SSH and JetBrains Gateway over `coder ssh`."
  type         = "bool"
  default      = "false"
  mutable      = true
  order        = 4
}

# --- Locals ---------------------------------------------------------------------------

locals {
  owner    = lower(data.coder_workspace_owner.me.name)
  name     = lower(data.coder_workspace.me.name)
  pod_name = "coder-${local.owner}-${local.name}"
  image    = "${var.workspace_image}@${var.workspace_image_digest}"
  home     = "/home/dev"
  uid      = 1000

  labels = {
    "app.kubernetes.io/name"       = "aegisx9-workspace"
    "app.kubernetes.io/part-of"    = "aegisx9"
    "app.kubernetes.io/managed-by" = "coder"
    "aegisx9.io/tier"              = "developer"
    "aegisx9.io/owner"             = local.owner
    "aegisx9.io/team"              = data.coder_parameter.team.value
    "owner"                        = local.owner
    "team"                         = data.coder_parameter.team.value
    "coder.workspace"              = local.name
  }

  # Everything the workspace exports to tools. Deliberately absent: ANTHROPIC_API_KEY and
  # ANTHROPIC_AUTH_TOKEN. The gateway authenticates the developer's own identity.
  env = {
    HOME                        = local.home
    USER                        = "dev"
    ANTHROPIC_BASE_URL          = var.gateway_url
    OTEL_EXPORTER_OTLP_ENDPOINT = var.otel_endpoint
    OTEL_SERVICE_NAME           = "aegisx9-workspace"
    OTEL_RESOURCE_ATTRIBUTES    = "aegisx9.owner=${local.owner},aegisx9.team=${data.coder_parameter.team.value},aegisx9.tier=developer"
    AEGISX9_WORKSPACE           = local.name
    AEGISX9_WORKSPACE_SSH_PORT  = tostring(var.ssh_port)
  }
}

# --- Coder agent ----------------------------------------------------------------------

resource "coder_agent" "main" {
  arch = var.agent_arch
  os   = "linux"

  # Startup: the home volume is empty on first start. Make it private, create the
  # directories the AegisX9 tooling expects, then start an unprivileged sshd for
  # VS Code Remote-SSH and JetBrains Gateway. No secret is read or written here.
  startup_script = templatefile("${path.module}/startup.sh.tftpl", {
    home     = local.home
    ssh_port = var.ssh_port
  })
  startup_script_behavior = "blocking"

  env = merge(local.env, {
    GIT_AUTHOR_NAME     = coalesce(data.coder_workspace_owner.me.full_name, data.coder_workspace_owner.me.name)
    GIT_AUTHOR_EMAIL    = data.coder_workspace_owner.me.email
    GIT_COMMITTER_NAME  = coalesce(data.coder_workspace_owner.me.full_name, data.coder_workspace_owner.me.name)
    GIT_COMMITTER_EMAIL = data.coder_workspace_owner.me.email
  })

  display_apps {
    vscode                 = true
    vscode_insiders        = false
    ssh_helper             = true
    port_forwarding_helper = false
    web_terminal           = true
  }

  metadata {
    display_name = "CPU"
    key          = "cpu"
    script       = "coder stat cpu"
    interval     = 10
    timeout      = 1
    order        = 1
  }
  metadata {
    display_name = "Memory"
    key          = "mem"
    script       = "coder stat mem"
    interval     = 10
    timeout      = 1
    order        = 2
  }
  metadata {
    display_name = "Home disk"
    key          = "home"
    script       = "coder stat disk --path ${local.home}"
    interval     = 60
    timeout      = 1
    order        = 3
  }
}

# Optional browser editor. Only enabled when the developer asks for it; code-server must
# already be in the image (the template installs nothing at runtime).
resource "coder_app" "code_server" {
  count        = data.coder_parameter.code_server.value ? 1 : 0
  agent_id     = coder_agent.main.id
  slug         = "code-server"
  display_name = "VS Code (browser)"
  icon         = "/icon/code.svg"
  url          = "http://localhost:13337/?folder=${local.home}"
  subdomain    = false
  share        = "owner"

  healthcheck {
    url       = "http://localhost:13337/healthz"
    interval  = 5
    threshold = 6
  }
}

# --- Kubernetes: persistent home, workspace pod -----------------------------------------

resource "kubernetes_persistent_volume_claim_v1" "home" {
  metadata {
    name      = "${local.pod_name}-home"
    namespace = var.namespace
    labels    = local.labels
    annotations = {
      "aegisx9.io/workspace-id" = data.coder_workspace.me.id
    }
  }
  wait_until_bound = false
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = var.storage_class == "" ? null : var.storage_class
    resources {
      requests = {
        storage = var.home_size
      }
    }
  }
}

resource "kubernetes_pod_v1" "main" {
  # Present only while the workspace is started; the PVC above outlives stop/start.
  count = data.coder_workspace.me.start_count

  metadata {
    name      = local.pod_name
    namespace = var.namespace
    labels    = local.labels
    annotations = {
      "aegisx9.io/workspace-id" = data.coder_workspace.me.id
      "aegisx9.io/image-digest" = var.workspace_image_digest
    }
  }

  spec {
    restart_policy                  = "Never"
    automount_service_account_token = false
    enable_service_links            = false

    security_context {
      run_as_user     = local.uid
      run_as_group    = local.uid
      fs_group        = local.uid
      run_as_non_root = true
      seccomp_profile {
        type = "RuntimeDefault"
      }
    }

    dynamic "image_pull_secrets" {
      for_each = var.image_pull_secret == "" ? [] : [var.image_pull_secret]
      content {
        name = image_pull_secrets.value
      }
    }

    container {
      name              = "dev"
      image             = local.image
      image_pull_policy = "IfNotPresent"
      command           = ["sh", "-c", coder_agent.main.init_script]

      security_context {
        run_as_user                = local.uid
        run_as_group               = local.uid
        run_as_non_root            = true
        allow_privilege_escalation = false
        privileged                 = false
        read_only_root_filesystem  = true
        capabilities {
          drop = ["ALL"]
        }
        seccomp_profile {
          type = "RuntimeDefault"
        }
      }

      env {
        name  = "CODER_AGENT_TOKEN"
        value = coder_agent.main.token
      }
      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }

      resources {
        requests = {
          cpu    = data.coder_parameter.cpu.value
          memory = "${data.coder_parameter.memory.value}Gi"
        }
        limits = {
          cpu    = data.coder_parameter.cpu.value
          memory = "${data.coder_parameter.memory.value}Gi"
        }
      }

      volume_mount {
        name       = "home"
        mount_path = local.home
      }
      volume_mount {
        name       = "tmp"
        mount_path = "/tmp"
      }

      # The agent binary is the container's main process; if it stops, the pod is dead.
      liveness_probe {
        exec {
          command = ["sh", "-c", "pgrep -x coder >/dev/null"]
        }
        initial_delay_seconds = 60
        period_seconds        = 30
        failure_threshold     = 3
      }
      readiness_probe {
        exec {
          command = ["sh", "-c", "pgrep -x coder >/dev/null"]
        }
        initial_delay_seconds = 10
        period_seconds        = 15
      }
    }

    volume {
      name = "home"
      persistent_volume_claim {
        claim_name = kubernetes_persistent_volume_claim_v1.home.metadata[0].name
      }
    }
    volume {
      name = "tmp"
      empty_dir {
        size_limit = "4Gi"
      }
    }
  }
}

# Shown on the workspace page so a developer can see exactly what they are running.
resource "coder_metadata" "workspace" {
  count       = data.coder_workspace.me.start_count
  resource_id = kubernetes_pod_v1.main[0].id
  item {
    key   = "image"
    value = local.image
  }
  item {
    key   = "gateway"
    value = var.gateway_url
  }
  item {
    key   = "cpu / memory"
    value = "${data.coder_parameter.cpu.value} cores / ${data.coder_parameter.memory.value} GiB"
  }
  item {
    key   = "team"
    value = data.coder_parameter.team.value
  }
}
