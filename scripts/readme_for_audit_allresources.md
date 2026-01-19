Resource-by-Resource Clarification
1. Amazon EC2 (Instances)
API counts running + stopped instances

Console may show:

Recently terminated instances

Filtered states

Terminated instances are intentionally excluded

2. Elastic Load Balancing
Console shows combined count of:

Application Load Balancers (ALB)

Network Load Balancers (NLB)

Classic Load Balancers

APIs separate these into:

elbv2 → ALB + NLB

elb → Classic ELB

Initial mismatch was due to Classic ELB being a separate legacy service

3. Amazon VPC
API counts:

All VPCs (default + custom)

We can remove Default VPCs to reduce the unnecessary increase in count

4. Amazon S3
Global service

if a bucket is used only as a replication target (for CRR or SRR), AWS still counts it as a normal S3 bucket.

5. AWS Lambda
API counts functions only

6. Amazon ECS
Audit counts:

ECS clusters

Console often highlights:

Services

Running tasks

These are distinct resource types
✔ Cluster-only counting is intentional

7. Amazon ECR
Audit counts:

Repositories

Console may also show:

Image count

Untagged images

8. Amazon RDS
AWS APIs treat two different resource types separately:

Standard RDS instances

Aurora clusters

The audit follows AWS API behavior, reporting:

Count of RDS DB instances

Count of Aurora DB clusters
as separate line items.
✔ Expected difference unless combined

9. RDS Snapshots
API includes:

Automated snapshots

Manual snapshots

Shared snapshots

10. AWS Backup
Audit counts:

Backup vaults

Recovery points per vault

we may also show:

Cross-region copies

Cross-account shared recovery points
✔ Cross-region copies are not included

11. AWS CloudWatch
API counts:

Metric alarms

Composite alarms

Console filters can hide alarm types (ECS auto created )
✔ Audit matches total alarms

12. AWS CloudTrail
API includes:

Multi-region trails

Organization trails

13. AWS GuardDuty
Audit counts:

Detectors only


14. AWS WAF
Two distinct scopes:

REGIONAL

CLOUDFRONT (Global)

Audit counts

The audit currently counts Regional Web ACLs using regional AWS APIs.

CloudFront WAFs require a separate global query

WAFs associated with CloudFront are global resources

They are not returned by regional WAF API calls

They must be queried separately using the global (us-east-1) endpoint


15. AWS Secrets Manager
API includes:

Active secrets

Secrets scheduled for deletion

16. AWS KMS
API returns:

Customer-managed keys

AWS-managed keys

17. AWS Certificate Manager (ACM)
Audit counts ACTIVE (ISSUED) certificates only

Console may show:

Expired

Pending validation

Failed certificates
✔ Audit matches “Active certificates” view

18. AWS Systems Manager (SSM)
Audit counts:

Managed instances
✔ API count reflects managed resources only

19. Amazon Route 53
Global service

API includes:

Public hosted zones

Private hosted zones

20. Amazon ElastiCache
API counts:

Cache clusters

Console may group replication groups
 Count differences are grouping-related

21. Amazon Neptune
API counts:

DB clusters  running + stopped 
✔ Audit includes all clusters

22. AWS Glue
Audit counts:

Databases

 

23. Amazon SES
Audit counts:

Identities

Console may show:

Verified domains

Emails separately
✔ Identity count is expected

24. Amazon Location Service
Regionally available

Not supported in all regions
✔ Unsupported regions are skipped

25. AWS End User Messaging
Not enabled in all regions
✔ API skips unsupported endpoints

26. AWS Elastic Disaster Recovery (DRS)
API counts:

Source servers

27. AWS CloudFormation
The audit script counts CloudFormation Stacks 

CREATE_COMPLETE

UPDATE_COMPLETE

It intentionally excludes:

Deleted stacks

Failed/rolled-back stacks (unless explicitly included)

StackSets

Nested stacks counted separately from parents (to avoid double counting)

28. AWS SQS

The audit script counts all SQS queues returned by the API using:

list_queues()

This includes:

Standard queues

FIFO queues

Queues with or without DLQs

Encrypted and unencrypted queues