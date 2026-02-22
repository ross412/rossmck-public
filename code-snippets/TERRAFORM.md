# Terraform Code

Terraform is used to deploy IaC into AWS.

1. Cloudflare only on ingress from known IPs

```
ingress {
  description = "HTTPS (Cloudflare proxy IPs only)"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    ...
  ]
}
```

2. SSH locked to single local IP

```
ingress {
  description = "SSH"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [var.my_ip_cidr]
}
```

3. SSM as alternative to SSH

```
resource "aws_iam_role" "k3s_ssm" {
  name = "k3s-ssm-role"
  assume_role_policy = jsonencode({
    ...
    Principal = { Service = "ec2.amazonaws.com" }
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```

4. Set Elastic IP for Cloudflare

```
resource "aws_eip" "k3s" {
  instance = aws_instance.k3s.id
  domain   = "vpc"
}
```

5. Preventative fix to make sure SSH isn't accidentally misconfigured 

```
variable "my_ip_cidr" {
  type        = string
  description = "Your public IP in CIDR form for SSH access, e.g. 1.2.3.4/32"
}
```
