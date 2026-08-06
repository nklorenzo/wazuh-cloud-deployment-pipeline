resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tpl", {
    wazuh_ip = aws_instance.web.public_ip
  })
  filename = "${path.module}/../ansible/inventory.ini"
}
