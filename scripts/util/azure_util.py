from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network.v2020_06_01.models import NetworkSecurityGroup
from azure.mgmt.network.v2020_06_01.models import SecurityRule
import os

sgx_1_core = "Standard_DC1s_v2"
sgx_2_core = "Standard_DC2s_v2"
sgx_4_core = "Standard_DC4s_v2"
sgx_8_core = "Standard_DC8s_v2"

RESOURCE_GROUP_NAME = "scalable_oram_resource_group"
VNET_NAME = "scalable_oram_vnet"
SUBNET_NAME = "scalable_oram_subnet"
IP_NAME = "scalable_oram_ip"
IP_CONFIG_NAME = "scalable_oram_ip_config"
SEC_GROUP_NAME = "scalable_oram_sec_group"
NIC_NAME = "scalable_oram_nic"

USERNAME = "azureuser"
DEFAULT_PASSWORD = "scalable_oram"
LOCATION = "eastus"

class AzureSetup:
    def __init__(self, resource_group_name):
        self.name = resource_group_name
        self.resource_group_name = "%s_resource_group" % resource_group_name
        self.vnet_name = "%s_vnet" % resource_group_name
        self.subnet_name = "%s_subnet" % resource_group_name
        self.ip_name = "%s_ip" % resource_group_name
        self.ip_config_name = "%s_ip_config" % resource_group_name
        self.sec_group_name = "%s_sec_group" % resource_group_name
        self.nic_name = "%s_nic" % resource_group_name
        self.initialized = False
    
    def runAzureSetup(self, location):
        credential = AzureCliCredential()
        subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
        resource_client = ResourceManagementClient(credential, subscription_id)
        rg_result = resource_client.resource_groups.create_or_update(self.resource_group_name,
                {
                    "location": location
                }
            )
        print(("Provisioned resource group %s in the %s region") % (rg_result.name, rg_result.location))
        return ComputeManagementClient(credential, subscription_id), NetworkManagementClient(credential, subscription_id)

    def cleanupAzure(self):
        credential = AzureCliCredential()
        subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
        resource_client = ResourceManagementClient(credential, subscription_id)
        
        poller = resource_client.resource_groups.begin_delete(self.resource_group_name)
        result = poller.result()
        print(("Deleted resource group %s") % (self.resource_group_name))
    
    def startAzureInstance(self, compute_client, network_client, name, instance_type, location, image_path, ssh_key_data):
        ip_name = self.ip_name + "_" + name
        ip_config_name = self.ip_config_name + "_" + name
        nic_name = self.nic_name + "_" + name
        vm_name = self.name + "_" + name
        vm_name = vm_name.replace("_", "-")     # azure gets mad if the name has _ in it

        if not self.initialized:
            self.initialized = True
            # Provision the virtual network and wait for completion
            poller = network_client.virtual_networks.begin_create_or_update(self.resource_group_name,
                self.vnet_name,
                {
                    "location": location,
                    "address_space": {
                        "address_prefixes": ["10.0.0.0/16"]
                    }
                }
            )

            vnet_result = poller.result()

            print(("Provisioned virtual network %s with address prefixes %s") % (vnet_result.name, vnet_result.address_space.address_prefixes))

            # Step 3: Provision the subnet and wait for completion
            poller = network_client.subnets.begin_create_or_update(self.resource_group_name, 
                self.vnet_name, self.subnet_name,
                { "address_prefix": "10.0.0.0/24" }
            )
            self.subnet_result = poller.result()

            print(("Provisioned virtual subnet %s with address prefix %s") % (self.subnet_result.name, self.subnet_result.address_prefix))

            poller = network_client.network_security_groups.begin_create_or_update(self.resource_group_name,
                self.sec_group_name,
                {
                    "location": location,
                    "security_rules": [
                    {
                        "name": "ssh",
                        "properties": {
                            "Protocol": "Tcp",
                            "Description": "allow SSH",
                            "SourceAddressPrefix": "*",
                            "SourcePortRange": "*",
                            "DestinationPortRange": "22",
                            "Priority": 100,
                            "DestinationAddressPrefix": "*",
                            "Access": "Allow",
                            "Direction": "Inbound",
                        }
                    },
                    {
                        "name": "application",
                        "properties": {
                            "Protocol": "Tcp",
                            "Description": "allow application",
                            "SourceAddressPrefix": "*",
                            "SourcePortRange": "*",
                            "DestinationPortRange": "12345",
                            "Priority": 101,
                            "DestinationAddressPrefix": "*",
                            "Access": "Allow",
                            "Direction": "Inbound",
                        }
                    }, 
                    {
                        "name": "application2",
                        "properties": {
                            "Protocol": "Tcp",
                            "Description": "allow application",
                            "SourceAddressPrefix": "*",
                            "SourcePortRange": "*",
                            "DestinationPortRange": "12346",
                            "Priority": 102,
                            "DestinationAddressPrefix": "*",
                            "Access": "Allow",
                            "Direction": "Inbound",
                        }
                    } 
                    ]
                }
            )
            self.sec_group_result = poller.result()
            self.initialized = True

        # Step 4: Provision an IP address and wait for completion
        poller = network_client.public_ip_addresses.begin_create_or_update(self.resource_group_name,
            ip_name,
            {
                "location": location,
                "sku": { "name": "Standard" },
                "public_ip_allocation_method": "Static",
                "public_ip_address_version" : "IPV4"
            }
        )

        ip_address_result = poller.result()

        print(("Provisioned public IP address %s with address %s") % (ip_address_result.name, ip_address_result.ip_address))

        #security_rule = SecurityRule(protocol='Tcp', source_address_prefix='Internet', 
        #                          source_port_range="*", destination_port_range="22", priority=100,
        #                          destination_address_prefix='*', access='Allow', direction='Inbound')
        #nsg_params = NetworkSecurityGroup(id=sec_group_name, location=location, security_rules=[security_rule])

        # Step 5: Provision the network interface client
        poller = network_client.network_interfaces.begin_create_or_update(self.resource_group_name,
            nic_name, 
            {
                "location": location,
                "ip_configurations": [ {
                    "name": ip_config_name,
                    "subnet": { "id": self.subnet_result.id },
                    "public_ip_address": {"id": ip_address_result.id }
                }],
                "network_security_group": {
                    "id": self.sec_group_result.id
                }
            }
        )

        nic_result = poller.result()

        print(("Provisioned network interface client %s") % (nic_result.name))
        
        print(("Provisioning virtual machine %s; this operation might take a few minutes.") % (vm_name))
        
        poller = compute_client.virtual_machines.begin_create_or_update(self.resource_group_name, vm_name,
        {
            "location": location,
            "storage_profile": {
                "image_reference": {
                    "id": image_path
                }
            },
            "hardware_profile": {
                "vm_size": instance_type
            },
            "os_profile": {
                "computer_name": vm_name,
                "admin_username": USERNAME,
                "linux_configuration": {
                    "disablePasswordAuthentication": True,
                    "ssh": {
                        "public_keys": [{
                            "path": "/home/{}/.ssh/authorized_keys".format(USERNAME),
                            "key_data": ssh_key_data
                        }]
                    }
                }
            },
            "network_profile": {
                "network_interfaces": [{
                    "id": nic_result.id,
                }]
            }
        })

        #vm_result = poller.result()
        print(("Provisioning virtual machine %s") % (vm_name))
        return poller, ip_address_result.ip_address, nic_result.ip_configurations[0].private_ip_address


    def startAzureInstances(self, compute_client, network_client, name_prefix, instance_type, location, image_path, ssh_key_data, num):
        vm_list = []
        ip_list = []
        private_ip_list = []
        for i in range(num):
            name = name_prefix + str(i)
            vm_poller, ip, private_ip = self.startAzureInstance(compute_client, network_client, name, instance_type, location, image_path, ssh_key_data)
            vm_list.append(vm_poller)
            ip_list.append(ip)
            private_ip_list.append(private_ip)
        for i in range(num):
            vm_list[i].result()
            print(("Provisioned virtual machine %s") % name)

        return vm_list, ip_list, private_ip_list

    def startAzureInstancesAsync(self, compute_client, network_client, name_prefix, instance_type, location, image_path, ssh_key_data, num):
        vm_list = []
        ip_list = []
        private_ip_list = []
        for i in range(num):
            name = name_prefix + str(i)
            vm_poller, ip, private_ip = self.startAzureInstance(compute_client, network_client, name, instance_type, location, image_path, ssh_key_data)
            vm_list.append(vm_poller)
            ip_list.append(ip)
            private_ip_list.append(private_ip)

        return vm_list, ip_list, private_ip_list

    def terminateAzureInstance(self, client, vm):
        client.virtual_machines.deallocate(self.resource_group_name, vm.name)
        print(("Terminated virtual machine %s") % (vm.name))

    def terminateAzureInstances(self, client, vm_list):
        for vm in vm_list:
            self.terminateAzureInstance(client, vm.name)
        print("Terminated all instances")
