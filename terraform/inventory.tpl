[wazuh]
wazuh-manager ansible_host=${wazuh_ip}

[wazuh:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/wazuh-key
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
