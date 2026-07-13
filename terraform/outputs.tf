output "instance_public_ip" {
  value       = aws_instance.web.public_ip
  description = "L'adresse IP publique de l'instance EC2"
}