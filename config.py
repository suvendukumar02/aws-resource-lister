AWS_SERVICES = {
    'accessanalyzer': {
        'function': 'list_analyzers',
        'operation': "[analyzer['arn'] for analyzer in response['analyzers']]"
    },
    'account': {
        'function': 'describe_account_attributes',
        'operation': "[attribute['AttributeName'] for attribute in response['AccountAttributes']]"
    },
    'acm': {
        'function': 'list_certificates',
        'operation': "[certificate['CertificateArn'] for certificate in response['CertificateSummaryList']]"
    },
    'acm-pca': {
        'function': 'list_certificates',
        'operation': "[certificate['Arn'] for certificate in response['CertificateAuthorities']]"
    },
    'alexaforbusiness': {
        'function': 'list_skills',
        'operation': "[skill['SkillId'] for skill in response['SkillSummaries']]"
    },
    'amp': {
        'function': 'list_workspaces',
        'operation': "[workspace['workspaceId'] for workspace in response['Workspaces']]"
    },
    'amplify': {
        'function': 'list_apps',
        'operation': "[app['appId'] for app in response['apps']]"
    },
    'amplifybackend': {
        'function': 'list_backend_jobs',
        'operation': "[job['appId'] for job in response['jobs']]"
    },
    'amplifyuibuilder': {
        'function': 'list_jobs',
        'operation': "[job['jobId'] for job in response['jobs']]"
    },
    'apigateway': {
        'function': 'get_rest_apis',
        'operation': "[api['name'] for api in response['items']]"
    },
    'apigatewaymanagementapi': {
        'function': 'get_connections',
        'operation': "[connection['connectionId'] for connection in response['Items']]"
    },
    'apigatewayv2': {
        'function': 'get_apis',
        'operation': "[api['Name'] for api in response['Items']]"
    },
    'appconfig': {
        'function': 'list_applications',
        'operation': "[application['Id'] for application in response['Items']]"
    },
    'appconfigdata': {
        'function': 'list_configuration_profiles',
        'operation': "[profile['ApplicationId'] for profile in response['Items']]"
    },
    'appfabric': {
        'function': 'list_environments',
        'operation': "[env['Name'] for env in response['Environments']]"
    },
    'appflow': {
        'function': 'list_flows',
        'operation': "[flow['flowName'] for flow in response['Flows']]"
    },
    'appintegrations': {
        'function': 'list_event_integrations',
        'operation': "[integration['Name'] for integration in response['EventIntegrations']]"
    },
    'application-autoscaling': {
        'function': 'describe_scalable_targets',
        'operation': "[target['ResourceId'] for target in response['ScalableTargets']]"
    },
    'application-insights': {
        'function': 'list_applications',
        'operation': "[app['AppName'] for app in response['ApplicationInfoList']]"
    },
    'applicationcostprofiler': {
        'function': 'list_report_definitions',
        'operation': "[definition['ReportId'] for definition in response['ReportDefinitions']]"
    },
    'appmesh': {
        'function': 'list_meshes',
        'operation': "[mesh['meshName'] for mesh in response['meshes']]"
    },
    'apprunner': {
        'function': 'list_services',
        'operation': "[service['ServiceArn'] for service in response['ServiceList']]"
    },
    'appstream': {
        'function': 'describe_fleets',
        'operation': "[fleet['FleetName'] for fleet in response['Fleets']]"
    },
    'appsync': {
        'function': 'list_graphql_apis',
        'operation': "[api['name'] for api in response['graphqlApis']]"
    },
    'arc-zonal-shift': {
        'function': 'list_associations',
        'operation': "[association['associationId'] for association in response['associations']]"
    },
    'artifact': {
        'function': 'describe_artifact',
        'operation': "[artifact['artifactId'] for artifact in response['Artifacts']]"
    },
    'athena': {
        'function': 'list_workgroups',
        'operation': "[workgroup['Name'] for workgroup in response['WorkGroups']]"
    },
    'auditmanager': {
        'function': 'list_assessment_frameworks',
        'operation': "[framework['id'] for framework in response['frameworkMetadataList']]"
    },
    'autoscaling': {
        'function': 'describe_auto_scaling_groups',
        'operation': "[group['AutoScalingGroupName'] for group in response['AutoScalingGroups']]"
    },
    'autoscaling-plans': {
        'function': 'describe_scaling_plans',
        'operation': "[plan['ScalingPlanName'] for plan in response['ScalingPlans']]"
    },
    'b2bi': {
        'function': 'list_artifacts',
        'operation': "[artifact['id'] for artifact in response['artifacts']]"
    },
    'backup': {
        'function': 'list_backup_jobs',
        'operation': "[job['BackupJobId'] for job in response['BackupJobs']]"
    },
    'backup-gateway': {
        'function': 'list_recovery_points_by_backup_vault',
        'operation': "[point['RecoveryPointArn'] for point in response['RecoveryPoints']]"
    },
    'backupstorage': {
        'function': 'list_backup_vaults',
        'operation': "[vault['BackupVaultName'] for vault in response['BackupVaultList']]"
    },
    'batch': {
        'function': 'describe_job_queues',
        'operation': "[queue['jobQueueName'] for queue in response['jobQueues']]"
    },
    'bcm-data-exports': {
        'function': 'list_exports',
        'operation': "[export['exportId'] for export in response['Exports']]"
    },
    'bedrock': {
        'function': 'list_artifacts',
        'operation': "[artifact['id'] for artifact in response['artifacts']]"
    },
    'bedrock-agent': {
        'function': 'list_agents',
        'operation': "[agent['id'] for agent in response['agents']]"
    },
    'bedrock-agent-runtime': {
        'function': 'list_operations',
        'operation': "[operation['id'] for operation in response['operations']]"
    },
    'bedrock-runtime': {
        'function': 'list_operations',
        'operation': "[operation['id'] for operation in response['operations']]"
    },
    'billingconductor': {
        'function': 'list_activities',
        'operation': "[activity['id'] for activity in response['activities']]"
    },
    'braket': {
        'function': 'list_quantum_tasks',
        'operation': "[task['taskArn'] for task in response['quantumTasks']]"
    },
    'budgets': {
        'function': 'describe_budgets',
        'operation': "[budget['BudgetName'] for budget in response['Budgets']]"
    },
    'ce': {
        'function': 'list_cost_categories',
        'operation': "[category['CostCategoryArn'] for category in response['CostCategoryReferences']]"
    },
    'chatbot': {
        'function': 'list_bots',
        'operation': "[bot['botId'] for bot in response['bots']]"
    },
    'chime': {
        'function': 'list_app_instances',
        'operation': "[instance['AppInstanceArn'] for instance in response['AppInstances']]"
    },
    'chime-sdk-identity': {
        'function': 'list_app_instances_admins',
        'operation': "[admin['AppInstanceAdminArn'] for admin in response['AppInstanceAdmins']]"
    },
    'chime-sdk-media-pipelines': {
        'function': 'list_pipelines',
        'operation': "[pipeline['MediaPipelineId'] for pipeline in response['MediaPipelines']]"
    },
    'chime-sdk-meetings': {
        'function': 'list_meeting_tags',
        'operation': "[tag['Key'] for tag in response['Tags']]"
    },
    'chime-sdk-messaging': {
        'function': 'list_channels',
        'operation': "[channel['ChannelArn'] for channel in response['Channels']]"
    },
    'chime-sdk-voice': {
        'function': 'list_phone_number_orders',
        'operation': "[order['PhoneNumberOrderId'] for order in response['PhoneNumberOrders']]"
    },
    'cleanrooms': {
        'function': 'list_clean_room_configs',
        'operation': "[config['CleanRoomArn'] for config in response['CleanRoomConfigs']]"
    },
    'cleanroomsml': {
        'function': 'list_ml_models',
        'operation': "[model['ModelId'] for model in response['MLModels']]"
    },
    'cloud9': {
        'function': 'describe_environments',
        'operation': "[env['environmentId'] for env in response['environments']]"
    },
    'cloudcontrol': {
        'function': 'list_controls',
        'operation': "[control['controlArn'] for control in response['controls']]"
    },
    'clouddirectory': {
        'function': 'list_directories',
        'operation': "[directory['DirectoryArn'] for directory in response['Directories']]"
    },
    'cloudformation': {
        'function': 'list_stacks',
        'operation': "[stack['StackName'] for stack in response['StackSummaries']]"
    },
    'cloudfront': {
        'function': 'list_distributions',
        'operation': "[distribution['Id'] for distribution in response['DistributionList']]"
    },
    'cloudfront-keyvaluestore': {
        'function': 'list_stores',
        'operation': "[store['Id'] for store in response['Stores']]"
    },
    'cloudhsm': {
        'function': 'list_hapgs',
        'operation': "[hapg['HapgArn'] for hapg in response['Hapgs']]"
    },
    'cloudhsmv2': {
        'function': 'list_clusters',
        'operation': "[cluster['HsmArn'] for cluster in response['Clusters']]"
    },
    'cloudsearch': {
        'function': 'list_domain_names',
        'operation': "[domain['DomainName'] for domain in response['DomainNames']]"
    },
    'cloudsearchdomain': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['Domains']]"
    },
    'cloudtrail': {
        'function': 'list_trails',
        'operation': "[trail['Name'] for trail in response['Trails']]"
    },
    'cloudtrail-data': {
        'function': 'list_events',
        'operation': "[event['EventId'] for event in response['Events']]"
    },
    'cloudwatch': {
        'function': 'list_dashboards',
        'operation': "[dashboard['DashboardName'] for dashboard in response['DashboardEntries']]"
    },
    'codeartifact': {
        'function': 'list_repositories',
        'operation': "[repo['Name'] for repo in response['repositories']]"
    },
    'codebuild': {
        'function': 'list_projects',
        'operation': "[project['name'] for project in response['projects']]"
    },
    'codecatalyst': {
        'function': 'list_sources',
        'operation': "[source['sourceId'] for source in response['Sources']]"
    },
    'codecommit': {
        'function': 'list_repositories',
        'operation': "[repo['repositoryName'] for repo in response['repositories']]"
    },
    'codeconnections': {
        'function': 'list_connections',
        'operation': "[connection['connectionId'] for connection in response['connections']]"
    },
    'codedeploy': {
        'function': 'list_applications',
        'operation': "[app['applicationName'] for app in response['applications']]"
    },
    'codeguru-reviewer': {
        'function': 'list_code_reviews',
        'operation': "[review['CodeReviewArn'] for review in response['CodeReviewSummaries']]"
    },
    'codeguru-security': {
        'function': 'list_findings',
        'operation': "[finding['id'] for finding in response['Findings']]"
    },
    'codeguruprofiler': {
        'function': 'list_profiling_groups',
        'operation': "[group['profilingGroupName'] for group in response['profilingGroupNames']]"
    },
    'codepipeline': {
        'function': 'list_pipelines',
        'operation': "[pipeline['name'] for pipeline in response['pipelines']]"
    },
    'codestar': {
        'function': 'list_projects',
        'operation': "[project['id'] for project in response['projects']]"
    },
    'codestar-connections': {
        'function': 'list_connections',
        'operation': "[connection['connectionId'] for connection in response['connections']]"
    },
    'codestar-notifications': {
        'function': 'list_notification_rules',
        'operation': "[rule['Id'] for rule in response['NotificationRules']]"
    },
    'cognito-identity': {
        'function': 'list_identity_pools',
        'operation': "[pool['IdentityPoolId'] for pool in response['IdentityPools']]"
    },
    'cognito-idp': {
        'function': 'list_user_pools',
        'operation': "[pool['Id'] for pool in response['UserPools']]"
    },
    'cognito-sync': {
        'function': 'list_identity_pool_usage',
        'operation': "[usage['IdentityPoolUsageId'] for usage in response['IdentityPoolUsages']]"
    },
    'comprehend': {
        'function': 'list_document_classification_jobs',
        'operation': "[job['JobId'] for job in response['DocumentClassificationJobPropertiesList']]"
    },
    'comprehendmedical': {
        'function': 'list_entities_detection_jobs',
        'operation': "[job['JobId'] for job in response['EntitiesDetectionJobPropertiesList']]"
    },
    'compute-optimizer': {
        'function': 'get_enrollment_status',
        'operation': "[status['status'] for status in response['status']]"
    },
    'config': {
        'function': 'describe_configuration_recorders',
        'operation': "[recorder['name'] for recorder in response['ConfigurationRecorders']]"
    },
    'connect': {
        'function': 'list_instances',
        'operation': "[instance['Id'] for instance in response['InstanceSummaryList']]"
    },
    'connect-contact-lens': {
        'function': 'list_realtime_contact_analysis_segments',
        'operation': "[segment['Id'] for segment in response['Segments']]"
    },
    'connectcampaigns': {
        'function': 'list_campaigns',
        'operation': "[campaign['Id'] for campaign in response['Campaigns']]"
    },
    'connectcases': {
        'function': 'list_cases',
        'operation': "[case['Id'] for case in response['Cases']]"
    },
    'connectparticipant': {
        'function': 'list_connections',
        'operation': "[connection['ConnectionToken'] for connection in response['Connections']]"
    },
    'controlcatalog': {
        'function': 'list_controls',
        'operation': "[control['name'] for control in response['Controls']]"
    },
    'controltower': {
        'function': 'list_guardrail_versions',
        'operation': "[version['Name'] for version in response['GuardrailVersions']]"
    },
    'cost-optimization-hub': {
        'function': 'list_reports',
        'operation': "[report['ReportId'] for report in response['Reports']]"
    },
    'cur': {
        'function': 'list_report_definitions',
        'operation': "[definition['ReportName'] for definition in response['ReportDefinitions']]"
    },
    'customer-profiles': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['Domains']]"
    },
    'databrew': {
        'function': 'list_datasets',
        'operation': "[dataset['Name'] for dataset in response['Datasets']]"
    },
    'dataexchange': {
        'function': 'list_data_sets',
        'operation': "[dataset['Name'] for dataset in response['DataSets']]"
    },
    'datapipeline': {
        'function': 'list_pipelines',
        'operation': "[pipeline['name'] for pipeline in response['pipelineIdList']]"
    },
    'datasync': {
        'function': 'list_locations',
        'operation': "[location['LocationArn'] for location in response['Locations']]"
    },
    'datazone': {
        'function': 'list_volumes',
        'operation': "[volume['VolumeId'] for volume in response['Volumes']]"
    },
    'dax': {
        'function': 'describe_clusters',
        'operation': "[cluster['ClusterName'] for cluster in response['Clusters']]"
    },
    'deadline': {
        'function': 'list_studios',
        'operation': "[studio['StudioId'] for studio in response['Studios']]"
    },
    'detective': {
        'function': 'list_graphs',
        'operation': "[graph['GraphArn'] for graph in response['GraphList']]"
    },
    'devicefarm': {
        'function': 'list_devices',
        'operation': "[device['arn'] for device in response['devices']]"
    },
    'devops-guru': {
        'function': 'list_resource_collection_filters',
        'operation': "[filter['Id'] for filter in response['ResourceCollectionFilters']]"
    },
    'directconnect': {
        'function': 'describe_direct_connect_gateways',
        'operation': "[gateway['directConnectGatewayId'] for gateway in response['directConnectGatewayAssociations']]"
    },
    'discovery': {
        'function': 'list_configurations',
        'operation': "[config['configurationId'] for config in response['configurations']]"
    },
    'dlm': {
        'function': 'get_lifecycle_policies',
        'operation': "[policy['PolicyId'] for policy in response['Policies']]"
    },
    'dms': {
        'function': 'describe_replication_instances',
        'operation': "[instance['ReplicationInstanceIdentifier'] for instance in response['ReplicationInstances']]"
    },
    'docdb': {
        'function': 'describe_db_clusters',
        'operation': "[cluster['DBClusterIdentifier'] for cluster in response['DBClusters']]"
    },
    'docdb-elastic': {
        'function': 'describe_elastic_ippools',
        'operation': "[pool['PoolId'] for pool in response['IPPoolConfigs']]"
    },
    'drs': {
        'function': 'list_proposals',
        'operation': "[proposal['Id'] for proposal in response['Proposals']]"
    },
    'ds': {
        'function': 'list_directories',
        'operation': "[directory['DirectoryId'] for directory in response['Directories']]"
    },
    'dynamodb': {
        'function': 'list_tables',
        'operation': "[table['TableName'] for table in response['TableNames']]"
    },
    'dynamodbstreams': {
        'function': 'list_streams',
        'operation': "[stream['StreamArn'] for stream in response['Streams']]"
    },
    'ebs': {
        'function': 'list_volume_snapshots',
        'operation': "[snapshot['SnapshotId'] for snapshot in response['Snapshots']]"
    },
    'ec2': {
        'function': 'describe_instances',
        'operation': "[instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]"
    },
    'ec2-instance-connect': {
        'function': 'describe_instance_credit_specifications',
        'operation': "[spec['instanceId'] for spec in response['instanceCreditSpecifications']]"
    },
    'ecr': {
        'function': 'describe_repositories',
        'operation': "[repo['repositoryName'] for repo in response['repositories']]"
    },
    'ecr-public': {
        'function': 'describe_repositories',
        'operation': "[repo['repositoryName'] for repo in response['repositories']]"
    },
    'ecs': {
        'function': 'list_clusters',
        'operation': "[cluster['clusterName'] for cluster in response['clusters']]"
    },
    'efs': {
        'function': 'describe_file_systems',
        'operation': "[filesystem['FileSystemId'] for filesystem in response['FileSystems']]"
    },
    'eks': {
        'function': 'list_clusters',
        'operation': "[cluster['name'] for cluster in response['clusters']]"
    },
    'eks-auth': {
        'function': 'list_clusters',
        'operation': "[cluster['name'] for cluster in response['clusters']]"
    },
    'elastic-inference': {
        'function': 'describe_accelerator_offerings',
        'operation': "[offering['acceleratorType'] for offering in response['acceleratorTypes']]"
    },
    'elasticache': {
        'function': 'describe_cache_clusters',
        'operation': "[cluster['CacheClusterId'] for cluster in response['CacheClusters']]"
    },
    'elasticbeanstalk': {
        'function': 'describe_applications',
        'operation': "[app['ApplicationName'] for app in response['Applications']]"
    },
    'elastictranscoder': {
        'function': 'list_pipelines',
        'operation': "[pipeline['Id'] for pipeline in response['Pipelines']]"
    },
    'elb': {
        'function': 'describe_load_balancers',
        'operation': "[loadbalancer['LoadBalancerName'] for loadbalancer in response['LoadBalancers']]"
    },
    'elbv2': {
        'function': 'describe_load_balancers',
        'operation': "[loadbalancer['LoadBalancerArn'] for loadbalancer in response['LoadBalancers']]"
    },
    'emr': {
        'function': 'list_clusters',
        'operation': "[cluster['Id'] for cluster in response['Clusters']]"
    },
    'emr-containers': {
        'function': 'list_virtual_clusters',
        'operation': "[cluster['id'] for cluster in response['virtualClusters']]"
    },
    'emr-serverless': {
        'function': 'list_virtual_clusters',
        'operation': "[cluster['id'] for cluster in response['virtualClusters']]"
    },
    'entityresolution': {
        'function': 'list_matching_jobs',
        'operation': "[job['JobId'] for job in response['JobList']]"
    },
    'es': {
        'function': 'list_domain_names',
        'operation': "[domain['DomainName'] for domain in response['DomainNames']]"
    },
    'events': {
        'function': 'list_event_buses',
        'operation': "[bus['Name'] for bus in response['EventBuses']]"
    },
    'evidently': {
        'function': 'list_labs',
        'operation': "[lab['labId'] for lab in response['Labs']]"
    },
    'finspace': {
        'function': 'list_environments',
        'operation': "[env['environmentId'] for env in response['environments']]"
    },
    'finspace-data': {
        'function': 'list_databases',
        'operation': "[db['databaseId'] for db in response['databases']]"
    },
    'firehose': {
        'function': 'list_delivery_streams',
        'operation': "[stream['DeliveryStreamName'] for stream in response['DeliveryStreamNames']]"
    },
    'fis': {
        'function': 'list_experiment_templates',
        'operation': "[template['id'] for template in response['experimentTemplates']]"
    },
    'fms': {
        'function': 'list_policies',
        'operation': "[policy['PolicyId'] for policy in response['PolicyList']]"
    },
    'forecast': {
        'function': 'list_datasets',
        'operation': "[dataset['DatasetArn'] for dataset in response['Datasets']]"
    },
    'forecastquery': {
        'function': 'list_datasets',
        'operation': "[dataset['DatasetArn'] for dataset in response['Datasets']]"
    },
    'frauddetector': {
        'function': 'list_detectors',
        'operation': "[detector['detectorId'] for detector in response['detectorList']]"
    },
    'freetier': {
        'function': 'list_opportunities',
        'operation': "[opportunity['id'] for opportunity in response['Opportunities']]"
    },
    'fsx': {
        'function': 'describe_file_systems',
        'operation': "[fs['FileSystemId'] for fs in response['FileSystems']]"
    },
    'gamelift': {
        'function': 'list_fleets',
        'operation': "[fleet['FleetId'] for fleet in response['FleetIds']]"
    },
    'glacier': {
        'function': 'list_vaults',
        'operation': "[vault['VaultName'] for vault in response['VaultList']]"
    },
    'globalaccelerator': {
        'function': 'list_accelerators',
        'operation': "[accelerator['AcceleratorArn'] for accelerator in response['Accelerators']]"
    },
    'glue': {
        'function': 'get_databases',
        'operation': "[db['Name'] for db in response['DatabaseList']]"
    },
    'grafana': {
        'function': 'list_workspaces',
        'operation': "[workspace['workspaceId'] for workspace in response['workspaces']]"
    },
    'greengrass': {
        'function': 'list_groups',
        'operation': "[group['Id'] for group in response['Groups']]"
    },
    'greengrassv2': {
        'function': 'list_core_devices',
        'operation': "[device['CoreDeviceThingName'] for device in response['CoreDevices']]"
    },
    'groundstation': {
        'function': 'list_ground_stations',
        'operation': "[station['groundStationId'] for station in response['groundstationList']]"
    },
    'guardduty': {
        'function': 'list_detectors',
        'operation': "[detector['DetectorId'] for detector in response['DetectorIds']]"
    },
    'health': {
        'function': 'describe_events',
        'operation': "[event['eventArn'] for event in response['events']]"
    },
    'healthlake': {
        'function': 'list_fhir_datastores',
        'operation': "[datastore['DatastoreArn'] for datastore in response['DatastorePropertiesList']]"
    },
    'honeycode': {
        'function': 'list_workbooks',
        'operation': "[workbook['workbookId'] for workbook in response['workbooks']]"
    },
    'iam': {
        'function': 'list_roles',
        'operation': "[role['RoleName'] for role in response['Roles']]"
    },
    'identitystore': {
        'function': 'list_directories',
        'operation': "[directory['DirectoryId'] for directory in response['Directories']]"
    },
    'imagebuilder': {
        'function': 'list_image_pipelines',
        'operation': "[pipeline['ImagePipelineArn'] for pipeline in response['imagePipelineList']]"
    },
    'importexport': {
        'function': 'list_jobs',
        'operation': "[job['JobId'] for job in response['Jobs']]"
    },
    'inspector': {
        'function': 'list_assessment_targets',
        'operation': "[target['assessmentTargetArn'] for target in response['assessmentTargetArns']]"
    },
    'inspector-scan': {
        'function': 'list_findings',
        'operation': "[finding['id'] for finding in response['findingArns']]"
    },
    'inspector2': {
        'function': 'list_assessment_targets',
        'operation': "[target['assessmentTargetArn'] for target in response['assessmentTargetArns']]"
    },
    'internetmonitor': {
        'function': 'list_tests',
        'operation': "[test['testId'] for test in response['tests']]"
    },
    'iot': {
        'function': 'list_things',
        'operation': "[thing['thingArn'] for thing in response['things']]"
    },
    'iot-data': {
        'function': 'list_things',
        'operation': "[thing['thingArn'] for thing in response['things']]"
    },
    'iot-jobs-data': {
        'function': 'list_jobs',
        'operation': "[job['jobArn'] for job in response['jobs']]"
    },
    'iot1click-devices': {
        'function': 'list_devices',
        'operation': "[device['DeviceArn'] for device in response['Devices']]"
    },
    'iot1click-projects': {
        'function': 'list_projects',
        'operation': "[project['projectArn'] for project in response['projects']]"
    },
    'iotanalytics': {
        'function': 'list_datastores',
        'operation': "[datastore['datastoreName'] for datastore in response['datastoreSummaries']]"
    },
    'iotdeviceadvisor': {
        'function': 'list_suite_runs',
        'operation': "[run['suiteRunArn'] for run in response['suiteRunsList']]"
    },
    'iotevents': {
        'function': 'list_detector_models',
        'operation': "[model['detectorModelName'] for model in response['detectorModelSummaries']]"
    },
    'iotevents-data': {
        'function': 'list_inputs',
        'operation': "[input['inputName'] for input in response['inputSummaries']]"
    },
    'iotfleethub': {
        'function': 'list_applications',
        'operation': "[app['applicationId'] for app in response['applications']]"
    },
    'iotfleetwise': {
        'function': 'list_fleets',
        'operation': "[fleet['fleetId'] for fleet in response['fleetSummaries']]"
    },
    'iotsecuretunneling': {
        'function': 'list_tunnels',
        'operation': "[tunnel['tunnelId'] for tunnel in response['tunnelSummaries']]"
    },
    'iotsitewise': {
        'function': 'list_asset_models',
        'operation': "[model['assetModelArn'] for model in response['assetModelSummaries']]"
    },
    'iotthingsgraph': {
        'function': 'get_upload_status',
        'operation': "[status['uploadId'] for status in response['uploadStatus']]"
    },
    'iottwinmaker': {
        'function': 'list_project_associations',
        'operation': "[association['associationId'] for association in response['associations']]"
    },
    'iotwireless': {
        'function': 'list_destinations',
        'operation': "[destination['DestinationArn'] for destination in response['DestinationList']]"
    },
    'ivs': {
        'function': 'list_channels',
        'operation': "[channel['arn'] for channel in response['channels']]"
    },
    'ivs-realtime': {
        'function': 'list_streams',
        'operation': "[stream['channelArn'] for stream in response['streams']]"
    },
    'ivschat': {
        'function': 'list_channels',
        'operation': "[channel['channelArn'] for channel in response['channels']]"
    },
    'kafka': {
        'function': 'list_clusters',
        'operation': "[cluster['clusterArn'] for cluster in response['ClusterInfoList']]"
    },
    'kafkaconnect': {
        'function': 'list_connectors',
        'operation': "[connector['connectorArn'] for connector in response['connectors']]"
    },
    'kendra': {
        'function': 'list_indices',
        'operation': "[index['Id'] for index in response['IndexConfigurationSummaryItems']]"
    },
    'kendra-ranking': {
        'function': 'list_query_suggestions_block_lists',
        'operation': "[blocklist['Id'] for blocklist in response['BlockListSummaryItems']]"
    },
    'keyspaces': {
        'function': 'list_keyspaces',
        'operation': "[keyspace['KeyspaceName'] for keyspace in response['Keyspaces']]"
    },
    'kinesis': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamNames']]"
    },
    'kinesis-video-archived-media': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamNames']]"
    },
    'kinesis-video-media': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamNames']]"
    },
    'kinesis-video-signaling': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamNames']]"
    },
    'kinesis-video-webrtc-storage': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamNames']]"
    },
    'kinesisanalytics': {
        'function': 'list_applications',
        'operation': "[app['ApplicationName'] for app in response['ApplicationSummaries']]"
    },
    'kinesisanalyticsv2': {
        'function': 'list_applications',
        'operation': "[app['ApplicationName'] for app in response['ApplicationSummaries']]"
    },
    'kinesisvideo': {
        'function': 'list_streams',
        'operation': "[stream['StreamName'] for stream in response['StreamInfoList']]"
    },
    'kms': {
        'function': 'list_keys',
        'operation': "[key['KeyId'] for key in response['Keys']]"
    },
    'lakeformation': {
        'function': 'list_data_lakes',
        'operation': "[lake['dataLakeId'] for lake in response['dataLakeList']]"
    },
    'lambda': {
        'function': 'list_functions',
        'operation': "[function['FunctionArn'] for function in response['Functions']]"
    },
    'launch-wizard': {
        'function': 'describe_images',
        'operation': "[image['ImageId'] for image in response['Images']]"
    },
    'lex-models': {
        'function': 'list_bots',
        'operation': "[bot['name'] for bot in response['bots']]"
    },
    'lex-runtime': {
        'function': 'list_bot_versions',
        'operation': "[version['botVersion'] for version in response['BotVersions']]"
    },
    'lexv2-models': {
        'function': 'list_bots',
        'operation': "[bot['botId'] for bot in response['botSummaries']]"
    },
    'lexv2-runtime': {
        'function': 'list_sessions',
        'operation': "[session['sessionId'] for session in response['sessionSummaries']]"
    },
    'license-manager': {
        'function': 'list_licenses',
        'operation': "[license['LicenseArn'] for license in response['Licenses']]"
    },
    'license-manager-linux-subscriptions': {
        'function': 'list_associations_for_license_configuration',
        'operation': "[association['ResourceArn'] for association in response['LicenseConfigurationAssociations']]"
    },
    'license-manager-user-subscriptions': {
        'function': 'list_license_specifications_for_resource',
        'operation': "[specification['LicenseConfigurationArn'] for specification in response['LicenseSpecifications']]"
    },
    'lightsail': {
        'function': 'get_active_names',
        'operation': "[name['name'] for name in response['activeNames']]"
    },
    'location': {
        'function': 'list_geofence_collections',
        'operation': "[collection['CollectionName'] for collection in response['Entries']]"
    },
    'logs': {
        'function': 'describe_log_groups',
        'operation': "[group['logGroupName'] for group in response['logGroups']]"
    },
    'lookoutequipment': {
        'function': 'list_inference_schedulers',
        'operation': "[scheduler['ModelName'] for scheduler in response['InferenceSchedulerSummaries']]"
    },
    'lookoutmetrics': {
        'function': 'list_anomaly_detectors',
        'operation': "[detector['AnomalyDetectorArn'] for detector in response['AnomalyDetectorSummaryList']]"
    },
    'lookoutvision': {
        'function': 'list_models',
        'operation': "[model['ModelVersion'] for model in response['Models']]"
    },
    'm2': {
        'function': 'list_launch_paths',
        'operation': "[path['launchPathId'] for path in response['launchPaths']]"
    },
    'machinelearning': {
        'function': 'get_data_sources',
        'operation': "[source['DataSourceId'] for source in response['Results']]"
    },
    'macie2': {
        'function': 'list_member_accounts',
        'operation': "[account['accountId'] for account in response['memberAccounts']]"
    },
    'managedblockchain': {
        'function': 'list_networks',
        'operation': "[network['id'] for network in response['Networks']]"
    },
    'managedblockchain-query': {
        'function': 'list_members',
        'operation': "[member['MemberId'] for member in response['Members']]"
    },
    'marketplace-agreement': {
        'function': 'list_agreements',
        'operation': "[agreement['AgreementArn'] for agreement in response['Agreements']]"
    },
    'marketplace-catalog': {
        'function': 'list_entities',
        'operation': "[entity['EntityArn'] for entity in response['EntitySummaryList']]"
    },
    'marketplace-deployment': {
        'function': 'list_deployments',
        'operation': "[deployment['DeploymentArn'] for deployment in response['DeploymentSummaryList']]"
    },
    'marketplace-entitlement': {
        'function': 'list_entitlements',
        'operation': "[entitlement['EntitlementArn'] for entitlement in response['Entitlements']]"
    },
    'marketplacecommerceanalytics': {
        'function': 'generate_data_set',
        'operation': "[dataset['DataSetRequestId'] for dataset in response['DataSetRequestId']]"
    },
    'mediaconnect': {
        'function': 'list_flows',
        'operation': "[flow['flowArn'] for flow in response['flows']]"
    },
    'mediaconvert': {
        'function': 'list_jobs',
        'operation': "[job['arn'] for job in response['jobs']]"
    },
    'medialive': {
        'function': 'list_channels',
        'operation': "[channel['arn'] for channel in response['channels']]"
    },
    'mediapackage': {
        'function': 'list_channels',
        'operation': "[channel['arn'] for channel in response['channels']]"
    },
    'mediapackage-vod': {
        'function': 'list_packaging_groups',
        'operation': "[group['arn'] for group in response['packagingGroups']]"
    },
    'mediapackagev2': {
        'function': 'list_channels',
        'operation': "[channel['arn'] for channel in response['channels']]"
    },
    'mediastore': {
        'function': 'list_containers',
        'operation': "[container['arn'] for container in response['Containers']]"
    },
    'mediastore-data': {
        'function': 'list_items',
        'operation': "[item['Name'] for item in response['Items']]"
    },
    'mediatailor': {
        'function': 'list_channels',
        'operation': "[channel['arn'] for channel in response['channels']]"
    },
    'medical-imaging': {
        'function': 'list_tags_for_resource',
        'operation': "[tag['TagKey'] for tag in response['Tags']]"
    },
    'memorydb': {
        'function': 'list_clusters',
        'operation': "[cluster['ARN'] for cluster in response['Clusters']]"
    },
    'meteringmarketplace': {
        'function': 'batch_meter_usage',
        'operation': "[meter['meteringRecordId'] for meter in response['Results']]"
    },
    'mgh': {
        'function': 'list_migrations',
        'operation': "[migration['migrationId'] for migration in response['migrationList']]"
    },
    'mgn': {
        'function': 'describe_mgn_resource_utilization',
        'operation': "[resource['resourceName'] for resource in response['items']]"
    },
    'migration-hub-refactor-spaces': {
        'function': 'list_home_region_controls',
        'operation': "[control['HomeRegion'] for control in response['HomeRegionControls']]"
    },
    'migrationhub-config': {
        'function': 'list_configurations',
        'operation': "[config['ConfigurationId'] for config in response['Configurations']]"
    },
    'migrationhuborchestrator': {
        'function': 'list_migration_tasks',
        'operation': "[task['MigrationTaskName'] for task in response['MigrationTaskSummaryList']]"
    },
    'migrationhubstrategy': {
        'function': 'list_migration_strategies',
        'operation': "[strategy['MigrationStrategyName'] for strategy in response['MigrationStrategies']]"
    },
    'mobile': {
        'function': 'list_projects',
        'operation': "[project['name'] for project in response['projects']]"
    },
    'mq': {
        'function': 'list_brokers',
        'operation': "[broker['BrokerArn'] for broker in response['BrokerSummaries']]"
    },
    'mturk': {
        'function': 'list_hits',
        'operation': "[hit['HITId'] for hit in response['HITs']]"
    },
    'mwaa': {
        'function': 'list_environments',
        'operation': "[env['Name'] for env in response['Environments']]"
    },
    'neptune': {
        'function': 'describe_db_clusters',
        'operation': "[cluster['DBClusterIdentifier'] for cluster in response['DBClusters']]"
    },
    'neptune-graph': {
        'function': 'list_tags_for_resource',
        'operation': "[tag['TagKey'] for tag in response['Tags']]"
    },
    'neptunedata': {
        'function': 'list_tags_for_resource',
        'operation': "[tag['TagKey'] for tag in response['Tags']]"
    },
    'network-firewall': {
        'function': 'list_firewalls',
        'operation': "[firewall['FirewallArn'] for firewall in response['Firewalls']]"
    },
    'networkmanager': {
        'function': 'list_global_networks',
        'operation': "[network['GlobalNetworkId'] for network in response['GlobalNetworks']]"
    },
    'networkmonitor': {
        'function': 'list_tests',
        'operation': "[test['TestArn'] for test in response['TestList']]"
    },
    'nimble': {
        'function': 'list_studios',
        'operation': "[studio['studioId'] for studio in response['studiolists']]"
    },
    'oam': {
        'function': 'list_streams',
        'operation': "[stream['StreamId'] for stream in response['StreamIDs']]"
    },
    'omics': {
        'function': 'list_workflows',
        'operation': "[workflow['workflowId'] for workflow in response['workflows']]"
    },
    'opensearch': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['DomainNames']]"
    },
    'opensearchserverless': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['DomainNames']]"
    },
    'opsworks': {
        'function': 'describe_stacks',
        'operation': "[stack['StackId'] for stack in response['Stacks']]"
    },
    'opsworkscm': {
        'function': 'describe_servers',
        'operation': "[server['ServerName'] for server in response['Servers']]"
    },
    'organizations': {
        'function': 'list_accounts',
        'operation': "[account['Id'] for account in response['Accounts']]"
    },
    'osis': {
        'function': 'list_streams',
        'operation': "[stream['StreamId'] for stream in response['StreamIDs']]"
    },
    'outposts': {
        'function': 'list_outposts',
        'operation': "[outpost['OutpostId'] for outpost in response['Outposts']]"
    },
    'panorama': {
        'function': 'list_devices',
        'operation': "[device['DeviceId'] for device in response['Devices']]"
    },
    'payment-cryptography': {
        'function': 'list_ledgers',
        'operation': "[ledger['LedgerName'] for ledger in response['Ledgers']]"
    },
    'payment-cryptography-data': {
        'function': 'list_currencies',
        'operation': "[currency['CurrencyCode'] for currency in response['Currencies']]"
    },
    'pca-connector-ad': {
        'function': 'list_connectors',
        'operation': "[connector['ConnectorId'] for connector in response['connectors']]"
    },
    'personalize': {
        'function': 'list_campaigns',
        'operation': "[campaign['campaignArn'] for campaign in response['campaigns']]"
    },
    'personalize-events': {
        'function': 'list_event_trackers',
        'operation': "[tracker['eventTrackerArn'] for tracker in response['eventTrackers']]"
    },
    'personalize-runtime': {
        'function': 'list_campaigns',
        'operation': "[campaign['campaignArn'] for campaign in response['campaigns']]"
    },
    'pi': {
        'function': 'list_metrics',
        'operation': "[metric['metricName'] for metric in response['Metrics']]"
    },
    'pinpoint': {
        'function': 'get_apps',
        'operation': "[app['Id'] for app in response['ApplicationsResponse']['Item']]"
    },
    'pinpoint-email': {
        'function': 'list_dedicated_ip_pools',
        'operation': "[pool['PoolName'] for pool in response['DedicatedIpPools']]"
    },
    'pinpoint-sms-voice': {
        'function': 'list_configuration_sets',
        'operation': "[set['ConfigurationSetName'] for set in response['ConfigurationSets']]"
    },
    'pinpoint-sms-voice-v2': {
        'function': 'list_configuration_sets',
        'operation': "[set['ConfigurationSetName'] for set in response['ConfigurationSets']]"
    },
    'pipes': {
        'function': 'list_pipelines',
        'operation': "[pipeline['pipelineName'] for pipeline in response['pipelineNames']]"
    },
    'polly': {
        'function': 'list_lexicons',
        'operation': "[lexicon['Name'] for lexicon in response['Lexicons']]"
    },
    'pricing': {
        'function': 'describe_services',
        'operation': "[service['ServiceCode'] for service in response['Services']]"
    },
    'privatenetworks': {
        'function': 'list_virtual_interfaces',
        'operation': "[interface['interfaceId'] for interface in response['virtualInterfaces']]"
    },
    'proton': {
        'function': 'list_environment_templates',
        'operation': "[template['templateName'] for template in response['environmentTemplates']]"
    },
    'qbusiness': {
        'function': 'list_asset_records',
        'operation': "[record['recordId'] for record in response['recordList']]"
    },
    'qconnect': {
        'function': 'list_contact_channels',
        'operation': "[channel['ChannelId'] for channel in response['contactChannelList']]"
    },
    'qldb': {
        'function': 'list_ledgers',
        'operation': "[ledger['Name'] for ledger in response['Ledgers']]"
    },
    'qldb-session': {
        'function': 'list_journal_kinesis_streams_for_ledger',
        'operation': "[stream['StreamId'] for stream in response['StreamIds']]"
    },
    'quicksight': {
        'function': 'list_dashboards',
        'operation': "[dashboard['Arn'] for dashboard in response['DashboardSummaryList']]"
    },
    'ram': {
        'function': 'list_permissions',
        'operation': "[permission['permissionArn'] for permission in response['permissions']]"
    },
    'rbin': {
        'function': 'list_recommenders',
        'operation': "[recommender['Name'] for recommender in response['recommenders']]"
    },
    'rds': {
        'function': 'describe_db_instances',
        'operation': "[instance['DBInstanceIdentifier'] for instance in response['DBInstances']]"
    },
    'rds-data': {
        'function': 'execute_statement',
        'operation': "[result['numberOfRecordsUpdated'] for result in response['updateResults']]"
    },
    'redshift': {
        'function': 'describe_clusters',
        'operation': "[cluster['ClusterIdentifier'] for cluster in response['Clusters']]"
    },
    'redshift-data': {
        'function': 'list_databases',
        'operation': "[db['DbName'] for db in response['Databases']]"
    },
    'redshift-serverless': {
        'function': 'list_databases',
        'operation': "[db['DbName'] for db in response['Databases']]"
    },
    'rekognition': {
        'function': 'list_collections',
        'operation': "[collection['CollectionId'] for collection in response['CollectionIds']]"
    },
    'repostspace': {
        'function': 'list_repositories',
        'operation': "[repo['repositoryId'] for repo in response['repositories']]"
    },
    'resiliencehub': {
        'function': 'list_resources',
        'operation': "[resource['resourceId'] for resource in response['resources']]"
    },
    'resource-explorer-2': {
        'function': 'list_resources',
        'operation': "[resource['resourceId'] for resource in response['resources']]"
    },
    'resource-groups': {
        'function': 'list_groups',
        'operation': "[group['GroupName'] for group in response['GroupIdentifiers']]"
    },
    'resourcegroupstaggingapi': {
        'function': 'get_resources',
        'operation': "[resource['ResourceARN'] for resource in response['ResourceTagMappingList']]"
    },
    'robomaker': {
        'function': 'list_robot_applications',
        'operation': "[app['arn'] for app in response['robotApplicationSummaries']]"
    },
    'rolesanywhere': {
        'function': 'list_roles',
        'operation': "[role['roleArn'] for role in response['Roles']]"
    },
    'route53': {
        'function': 'list_hosted_zones',
        'operation': "[zone['Id'] for zone in response['HostedZones']]"
    },
    'route53-recovery-cluster': {
        'function': 'list_recovery_groups',
        'operation': "[group['GroupArn'] for group in response['RecoveryGroupArn']]"
    },
    'route53-recovery-control-config': {
        'function': 'list_control_panels',
        'operation': "[panel['ControlPanelArn'] for panel in response['ControlPanels']]"
    },
    'route53-recovery-readiness': {
        'function': 'list_cell_readiness_checks',
        'operation': "[check['ReadinessCheckArn'] for check in response['ReadinessCheckArn']]"
    },
    'route53domains': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['Domains']]"
    },
    'route53profiles': {
        'function': 'list_instance_resources',
        'operation': "[resource['Id'] for resource in response['InstanceResources']]"
    },
    'route53resolver': {
        'function': 'list_resolver_dnssec_configs',
        'operation': "[config['Id'] for config in response['ResolverDnssecConfigs']]"
    },
    'rum': {
        'function': 'list_apps',
        'operation': "[app['appId'] for app in response['apps']]"
    },
    's3': {
        'function': 'list_buckets',
        'operation': "[bucket['Name'] for bucket in response['Buckets']]"
    },
    's3control': {
        'function': 'list_access_points',
        'operation': "[access_point['Name'] for access_point in response['AccessPointList']]"
    },
    's3outposts': {
        'function': 'list_endpoints',
        'operation': "[endpoint['EndpointArn'] for endpoint in response['Endpoints']]"
    },
    'sagemaker': {
        'function': 'list_notebook_instances',
        'operation': "[instance['NotebookInstanceArn'] for instance in response['NotebookInstances']]"
    },
    'sagemaker-a2i-runtime': {
        'function': 'list_human_loop_summaries',
        'operation': "[loop['HumanLoopName'] for loop in response['HumanLoopSummaries']]"
    },
    'sagemaker-edge': {
        'function': 'list_devices',
        'operation': "[device['DeviceName'] for device in response['Devices']]"
    },
    'sagemaker-featurestore-runtime': {
        'function': 'list_feature_groups',
        'operation': "[group['FeatureGroupArn'] for group in response['FeatureGroupSummaries']]"
    },
    'sagemaker-geospatial': {
        'function': 'list_ml_models',
        'operation': "[model['ModelName'] for model in response['Models']]"
    },
    'sagemaker-metrics': {
        'function': 'list_model_quality_job_definitions',
        'operation': "[definition['JobDefinitionName'] for definition in response['JobDefinitionSummaries']]"
    },
    'sagemaker-runtime': {
        'function': 'list_endpoint_configs',
        'operation': "[config['EndpointConfigName'] for config in response['EndpointConfigs']]"
    },
    'savingsplans': {
        'function': 'describe_savings_plans',
        'operation': "[plan['savingsPlanArn'] for plan in response['savingsPlans']]"
    },
    'scheduler': {
        'function': 'list_jobs',
        'operation': "[job['jobId'] for job in response['jobs']]"
    },
    'schemas': {
        'function': 'list_discoverers',
        'operation': "[discovery['DiscovererArn'] for discovery in response['Discoverers']]"
    },
    'sdb': {
        'function': 'list_domains',
        'operation': "[domain['DomainName'] for domain in response['DomainNames']]"
    },
    'secretsmanager': {
        'function': 'list_secrets',
        'operation': "[secret['ARN'] for secret in response['SecretList']]"
    },
    'securityhub': {
        'function': 'list_findings',
        'operation': "[finding['Id'] for finding in response['Findings']]"
    },
    'securitylake': {
        'function': 'list_managed_data_lakes',
        'operation': "[lake['DataLakeId'] for lake in response['dataLakes']]"
    },
    'serverlessrepo': {
        'function': 'list_applications',
        'operation': "[app['ApplicationId'] for app in response['Applications']]"
    },
    'service-quotas': {
        'function': 'list_service_quotas',
        'operation': "[quota['ServiceCode'] for quota in response['Quotas']]"
    },
    'servicecatalog': {
        'function': 'list_portfolios',
        'operation': "[portfolio['Id'] for portfolio in response['PortfolioDetails']]"
    },
    'servicecatalog-appregistry': {
        'function': 'list_applications',
        'operation': "[application['Id'] for application in response['Applications']]"
    },
    'servicediscovery': {
        'function': 'list_namespaces',
        'operation': "[namespace['Id'] for namespace in response['Namespaces']]"
    },
    'ses': {
        'function': 'list_identities',
        'operation': "[identity['IdentityType'] for identity in response['Identities']]"
    },
    'sesv2': {
        'function': 'list_email_identities',
        'operation': "[identity['IdentityType'] for identity in response['EmailIdentities']]"
    },
    'shield': {
        'function': 'list_protection_groups',
        'operation': "[group['ProtectionGroupId'] for group in response['ProtectionGroups']]"
    },
    'signer': {
        'function': 'list_signing_profiles',
        'operation': "[profile['profileName'] for profile in response['profiles']]"
    },
    'simspaceweaver': {
        'function': 'list_studio_components',
        'operation': "[component['componentId'] for component in response['components']]"
    },
    'sms': {
        'function': 'list_apps',
        'operation': "[app['appId'] for app in response['apps']]"
    },
    'sms-voice': {
        'function': 'list_configuration_sets',
        'operation': "[set['ConfigurationSetName'] for set in response['ConfigurationSets']]"
    },
    'snow-device-management': {
        'function': 'list_instances',
        'operation': "[instance['DeviceId'] for instance in response['instances']]"
    },
    'snowball': {
        'function': 'list_clusters',
        'operation': "[cluster['ClusterId'] for cluster in response['JobListEntries']]"
    },
    'sns': {
        'function': 'list_topics',
        'operation': "[topic['TopicArn'] for topic in response['Topics']]"
    },
    'sqs': {
        'function': 'list_queues',
        'operation': "[queue['QueueUrl'] for queue in response['QueueUrls']]"
    },
    'ssm': {
        'function': 'describe_instance_information',
        'operation': "[instance['InstanceId'] for instance in response['InstanceInformationList']]"
    },
    'ssm-contacts': {
        'function': 'list_contacts',
        'operation': "[contact['ContactArn'] for contact in response['Contacts']]"
    },
    'ssm-incidents': {
        'function': 'list_incidents',
        'operation': "[incident['Arn'] for incident in response['incidentRecordSummaries']]"
    },
    'ssm-sap': {
        'function': 'list_associations',
        'operation': "[association['Name'] for association in response['Associations']]"
    },
    'sso': {
        'function': 'list_instances',
        'operation': "[instance['InstanceId'] for instance in response['instances']]"
    },
    'sso-admin': {
        'function': 'list_instances',
        'operation': "[instance['InstanceId'] for instance in response['instances']]"
    },
    'sso-oidc': {
        'function': 'list_instances',
        'operation': "[instance['InstanceId'] for instance in response['instances']]"
    },
    'stepfunctions': {
        'function': 'list_state_machines',
        'operation': "[machine['stateMachineArn'] for machine in response['stateMachines']]"
    },
    'storagegateway': {
        'function': 'list_gateways',
        'operation': "[gateway['GatewayARN'] for gateway in response['Gateways']]"
    },
    'sts': {
        'function': 'get_caller_identity',
        'operation': "response['UserId']"
    },
    'supplychain': {
        'function': 'list_workflow_runs',
        'operation': "[run['RunId'] for run in response['Runs']]"
    },
    'support': {
        'function': 'describe_cases',
        'operation': "[case['caseId'] for case in response['cases']]"
    },
    'support-app': {
        'function': 'describe_cases',
        'operation': "[case['caseId'] for case in response['cases']]"
    },
    'swf': {
        'function': 'list_domains',
        'operation': "[domain['domainInfo']['name'] for domain in response['domainInfos']]"
    },
    'synthetics': {
        'function': 'list_canaries',
        'operation': "[canary['Name'] for canary in response['Canaries']]"
    },
    'textract': {
        'function': 'get_document_analysis',
        'operation': "[analysis['DocumentMetadata']['Pages']]"
    },
    'timestream-influxdb': {
        'function': 'list_databases',
        'operation': "[db['DatabaseName'] for db in response['Databases']]"
    },
    'timestream-query': {
        'function': 'list_databases',
        'operation': "[db['DatabaseName'] for db in response['Databases']]"
    },
    'timestream-write': {
        'function': 'list_databases',
        'operation': "[db['DatabaseName'] for db in response['Databases']]"
    },
    'tnb': {
        'function': 'list_environments',
        'operation': "[env['EnvironmentId'] for env in response['environments']]"
    },
    'transcribe': {
        'function': 'list_transcription_jobs',
        'operation': "[job['TranscriptionJobName'] for job in response['TranscriptionJobSummaries']]"
    },
    'transfer': {
        'function': 'list_servers',
        'operation': "[server['ServerId'] for server in response['Servers']]"
    },
    'translate': {
        'function': 'list_parallel_data',
        'operation': "[data['Name'] for data in response['ParallelDataPropertiesList']]"
    },
    'trustedadvisor': {
        'function': 'describe_trusted_advisor_checks',
        'operation': "[check['checkId'] for check in response['checks']]"
    },
    'verifiedpermissions': {
        'function': 'list_approval_rules_templates',
        'operation': "[template['ApprovalRuleTemplateName'] for template in response['ApprovalRuleTemplates']]"
    },
    'voice-id': {
        'function': 'list_domains',
        'operation': "[domain['DomainId'] for domain in response['Domains']]"
    },
    'vpc-lattice': {
        'function': 'list_gateways',
        'operation': "[gateway['GatewayARN'] for gateway in response['Gateways']]"
    },
    'waf': {
        'function': 'list_web_acls',
        'operation': "[acl['WebACLArn'] for acl in response['WebACLs']]"
    },
    'waf-regional': {
        'function': 'list_web_acls',
        'operation': "[acl['WebACLArn'] for acl in response['WebACLs']]"
    },
    'wafv2': {
        'function': 'list_web_acls',
        'operation': "[acl['ARN'] for acl in response['WebACLs']]"
    },
    'wellarchitected': {
        'function': 'list_workloads',
        'operation': "[workload['WorkloadId'] for workload in response['WorkloadSummaries']]"
    },
    'wisdom': {
        'function': 'list_knowledge_bases',
        'operation': "[base['knowledgeBaseId'] for base in response['knowledgeBaseList']]"
    },
    'workdocs': {
        'function': 'describe_users',
        'operation': "[user['UserId'] for user in response['Users']]"
    },
    'worklink': {
        'function': 'list_fleets',
        'operation': "[fleet['FleetArn'] for fleet in response['FleetSummaryList']]"
    },
    'workmail': {
        'function': 'list_organizations',
        'operation': "[org['OrganizationId'] for org in response['OrganizationSummaries']]"
    },
    'workmailmessageflow': {
        'function': 'list_rules',
        'operation': "[rule['Name'] for rule in response['Rules']]"
    },
    'workspaces': {
        'function': 'describe_workspaces',
        'operation': "[workspace['WorkspaceId'] for workspace in response['Workspaces']]"
    },
    'workspaces-thin-client': {
        'function': 'describe_workspaces',
        'operation': "[workspace['WorkspaceId'] for workspace in response['Workspaces']]"
    },
    'workspaces-web': {
        'function': 'describe_workspaces',
        'operation': "[workspace['WorkspaceId'] for workspace in response['Workspaces']]"
    },
    'xray': {
        'function': 'get_sampling_rules',
        'operation': "[rule['RuleName'] for rule in response['SamplingRuleRecords']]"
    }
}
