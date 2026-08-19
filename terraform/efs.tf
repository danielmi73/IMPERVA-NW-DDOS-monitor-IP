# Amazon EFS File System for SQLite DB Persistence (/app/data)
resource "aws_efs_file_system" "data" {
  creation_token   = "${var.app_name}-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  encrypted        = true

  tags = {
    Name = "${var.app_name}-efs"
  }
}

# EFS Access Point for /app/data
resource "aws_efs_access_point" "data" {
  file_system_id = aws_efs_file_system.data.id

  posix_user {
    gid = 1000
    uid = 1000
  }

  root_directory {
    path = "/data"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "0755"
    }
  }

  tags = {
    Name = "${var.app_name}-efs-access-point"
  }
}

# EFS Mount Targets in Private Subnets
resource "aws_efs_mount_target" "target_1" {
  file_system_id  = aws_efs_file_system.data.id
  subnet_id       = aws_subnet.private_1.id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_mount_target" "target_2" {
  file_system_id  = aws_efs_file_system.data.id
  subnet_id       = aws_subnet.private_2.id
  security_groups = [aws_security_group.efs.id]
}
