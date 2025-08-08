data "aws_region" "current" {}
# Security Group for ECS Tasks
# add an elastic load balancer and security group for the load balancer.  Then the ingress rule here for the ECS task will reference the load balancer security group.id
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.namespace}-${var.app_name}-security-group"
  description = "AIST-9408 - for phpIPAM"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
# ECS Task Definition
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.namespace}-${var.app_name}"
  requires_compatibilities = ["FARGATE"]
  network_mode            = "awsvpc"
  cpu                     = 256
  memory                  = 512
  execution_role_arn      = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn
  container_definitions = jsonencode([
    {
      name  = var.app_name
      image = "${aws_ecr_repository.app.repository_url}:latest"
      secrets = [
        {
          name      = "ENCRYPTION_KEY"
          valueFrom = "${aws_secretsmanager_secret.configuration.arn}:ENCRYPTION_KEY::"
        },
        {
          name      = "AUTH_KEY"
          valueFrom = "${aws_secretsmanager_secret.configuration.arn}:AUTH_KEY::"
        }
      ]
      mountPoints = [
        {
          sourceVolume  = "${var.namespace}-${var.app_name}-efs-volume"
          containerPath = "/data"
          readOnly     = false
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_task.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
    },
  ])
  volume {
    name = "${var.namespace}-${var.app_name}-efs-volume"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.main.id
      root_directory = "/"
      transit_encryption = "ENABLED"
      transit_encryption_port = 2049
      authorization_config {
        iam = "ENABLED"
        access_point_id = aws_efs_access_point.app.id
      }
    }
  }
}
# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.namespace}-${var.app_name}-ecs-task-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Log Group for ECS Exec logging
resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/exec-logs"
  retention_in_days = 14
}
# Additional policy for ECS Exec logging
resource "aws_iam_role_policy" "ecs_exec_logging" {
  name = "ecs-exec-logging"
  role = aws_iam_role.ecs_task_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.ecs_exec.arn}:*"
        ]
      }
    ]
  })
}
# KMS key for ECS Exec
resource "aws_kms_key" "ecs_exec" {
  description             = "KMS key for ECS Exec"
  deletion_window_in_days = 7
  enable_key_rotation    = true
}
resource "aws_kms_alias" "ecs_exec" {
  name          = "alias/${var.namespace}-${var.app_name}/ecs-exec"
  target_key_id = aws_kms_key.ecs_exec.key_id
}
# Add KMS permissions to task role
resource "aws_iam_role_policy" "ecs_task_kms" {
  name = "${var.namespace}-${var.app_name}-ecs-task-kms"
  role = aws_iam_role.ecs_task_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.ecs_exec.arn
        ]
      }
    ]
  })
}
# ECS permission to configuration secret
# You probably wont needs this, I think everything the app needs is in its own configuration file.
resource "aws_iam_role_policy" "ecs_task_execution_secrets" {
  name = "${var.namespace}-${var.app_name}-secrets"
  role = aws_iam_role.ecs_task_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [aws_secretsmanager_secret.configuration.arn]
      }
    ]
  })
}
# IAM Role for ECS Tasks
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.namespace}-${var.app_name}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}
# ECS Service
resource "aws_ecs_service" "app" {
  name            = "${var.namespace}-${var.app_name}-service"
  cluster         = aws_ecs_cluster.main.id  # Updated to use the new cluster
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  enable_execute_command = true
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
}
# ECR Repository
resource "aws_ecr_repository" "app" {
  depends_on = [ aws_kms_key.ecs_exec ]
  name                 = "${var.namespace}-${var.app_name}"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
  }
}
# ECR Repository Policy
resource "aws_ecr_repository_policy" "app_policy" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPull"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}
# ECR Lifecycle Policy
resource "aws_ecr_lifecycle_policy" "app_lifecycle" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
# Add ECR permissions to ECS Task Execution Role
resource "aws_iam_role_policy" "ecs_task_execution_ecr" {
  name = "${var.namespace}-${var.app_name}-ecs-task-execution-ecr"
  role = aws_iam_role.ecs_task_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })
}
# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.namespace}-${var.app_name}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.ecs_exec.arn
      logging    = "OVERRIDE"
      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name    = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }
}
# CloudWatch Log Group for ECS Task
resource "aws_cloudwatch_log_group" "ecs_task" {
  name              = "/ecs/${var.namespace}-${var.app_name}"
  retention_in_days = 30  # Adjust retention period as needed
}
resource "aws_iam_role_policy" "ecs_task_execution_logs" {
  name = "${var.namespace}-${var.app_name}-logs"
  role = aws_iam_role.ecs_task_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.ecs_task.arn}:*"
        ]
      }
    ]
  })
}
resource "aws_secretsmanager_secret" "configuration" {
  name = "${var.namespace}-${var.app_name}-config"
}