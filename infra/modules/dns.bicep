@description('Domain name')
param domainName string

@description('Subdomain prefix')
param subdomain string

@description('Application Gateway public IP address')
param applicationGatewayPublicIp string

// DNS Zone
resource dnsZone 'Microsoft.Network/dnsZones@2023-07-01-preview' = {
  name: domainName
  location: 'global'
  tags: {
    managedBy: 'bicep'
  }
}

// A Record for subdomain
resource aRecord 'Microsoft.Network/dnsZones/A@2023-07-01-preview' = {
  parent: dnsZone
  name: subdomain
  properties: {
    TTL: 3600
    ARecords: [
      {
        ipv4Address: applicationGatewayPublicIp
      }
    ]
  }
}

output dnsZoneId string = dnsZone.id
output nameServers array = dnsZone.properties.nameServers