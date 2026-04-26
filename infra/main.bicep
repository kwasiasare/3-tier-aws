targetScope = 'resourceGroup'

@description('Environment type for tagging and naming resources')
@allowed(['Development', 'Staging', 'Production'])
param environment string = 'Production'

@description('Project name for resource naming')
param projectName string = 'tier3'

@description('Primary deployment region')
param location string = 'eastus2'

@description('Domain name for DNS configuration')
param domainName string = 'spreadcom.org'

@description('Subdomain prefix for application')
param subdomain string = 'app'

@description('Virtual network CIDR block')
param vnetCidr string = '10.0.0.0/16'

@description('Public subnet CIDR block for Application Gateway')
param publicSubnetCidr string = '10.0.1.0/24'

@description('Private subnet CIDR block for Container Apps')
param privateSubnetCidr string = '10.0.2.0/24'

@description('Database subnet CIDR block for private endpoints')
param databaseSubnetCidr string = '10.0.3.0/24'

@description('Minimum number of container app replicas')
@minValue(0)
@maxValue(10)
param minReplicas int = 2

@description('Maximum number of container app replicas')
@minValue(1)
@maxValue(20)
param maxReplicas int = 4

@description('Container image for the application')
param containerImage string = 'nginx:latest'

// Monitoring Module
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    projectName: projectName
    environment: environment
  }
}

// Network Module
module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    projectName: projectName
    environment: environment
    vnetCidr: vnetCidr
    publicSubnetCidr: publicSubnetCidr
    privateSubnetCidr: privateSubnetCidr
    databaseSubnetCidr: databaseSubnetCidr
  }
}

// Security Module
module security 'modules/security.bicep' = {
  name: 'security'
  params: {
    location: location
    projectName: projectName
    environment: environment
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

// Storage Module
module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    projectName: projectName
    environment: environment
    databaseSubnetId: network.outputs.databaseSubnetId
    keyVaultId: security.outputs.keyVaultId
    storagePrivateDnsZoneId: network.outputs.storagePrivateDnsZoneId
  }
}

// Database Module
module database 'modules/database.bicep' = {
  name: 'database'
  params: {
    location: location
    projectName: projectName
    environment: environment
    databaseSubnetId: network.outputs.databaseSubnetId
    keyVaultId: security.outputs.keyVaultId
    cosmosPrivateDnsZoneId: network.outputs.cosmosPrivateDnsZoneId
  }
}

// Compute Module
module compute 'modules/compute.bicep' = {
  name: 'compute'
  params: {
    location: location
    projectName: projectName
    environment: environment
    privateSubnetId: network.outputs.privateSubnetId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    applicationInsightsConnectionString: monitoring.outputs.applicationInsightsConnectionString
    minReplicas: minReplicas
    maxReplicas: maxReplicas
    containerImage: containerImage
    cosmosDbEndpoint: database.outputs.cosmosDbEndpoint
    storageAccountName: storage.outputs.storageAccountName
    keyVaultUri: security.outputs.keyVaultUri
  }
}

// Gateway Module
module gateway 'modules/gateway.bicep' = {
  name: 'gateway'
  params: {
    location: location
    projectName: projectName
    environment: environment
    publicSubnetId: network.outputs.publicSubnetId
    containerAppFqdn: compute.outputs.containerAppFqdn
  }
}

// DNS Module
module dns 'modules/dns.bicep' = {
  name: 'dns'
  params: {
    domainName: domainName
    subdomain: subdomain
    applicationGatewayPublicIp: gateway.outputs.applicationGatewayPublicIp
  }
}

// Grant Container App access to resources
module rbac 'modules/rbac.bicep' = {
  name: 'rbac'
  params: {
    containerAppPrincipalId: compute.outputs.containerAppPrincipalId
    cosmosDbAccountId: database.outputs.cosmosDbAccountId
    storageAccountId: storage.outputs.storageAccountId
    keyVaultId: security.outputs.keyVaultId
  }
}

// Outputs
output primaryUrl string = 'https://${subdomain}.${domainName}'
output containerAppUrl string = 'https://${compute.outputs.containerAppFqdn}'
output cosmosDbEndpoint string = database.outputs.cosmosDbEndpoint
output storageAccountName string = storage.outputs.storageAccountName
output keyVaultUri string = security.outputs.keyVaultUri