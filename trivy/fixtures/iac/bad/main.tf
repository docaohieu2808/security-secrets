# Deliberately insecure Terraform for the IaC scan demo.
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs-bucket"
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name        = "open"
  description = "Allows SSH from anywhere"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
