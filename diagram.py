from diagrams import Cluster, Diagram, Edge
from diagrams.aws.analytics import Athena, Glue
from diagrams.aws.compute import Lambda
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import Eventbridge
from diagrams.aws.management import Cloudtrail
from diagrams.aws.ml import Bedrock
from diagrams.aws.security import SecretsManager, SecurityHub
from diagrams.aws.storage import S3

graph_attrs = {
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.8",
    "ranksep": "1.0",
    "nodesep": "0.4",
    "splines": "ortho",
}

node_attrs = {
    "fontsize": "10",
}

edge_attrs = {
    "fontsize": "9",
}

with Diagram(
    "Secrets Lifecycle and Rotation Readiness Platform",
    filename="docs/architecture",
    outformat="png",
    show=False,
    graph_attr=graph_attrs,
    node_attr=node_attrs,
    edge_attr=edge_attrs,
):
    schedule = Eventbridge("EventBridge\nscan schedule")

    with Cluster("Secret sources (metadata only)"):
        secrets = SecretsManager("Secrets Manager")
        ssm = SecretsManager("SSM SecureString")
        iam_keys = SecretsManager("IAM access keys")

    with Cluster("Pipeline"):
        scanner = Lambda("secops-scanner\nGo, worker pool")
        analyzer = Lambda("secops-analyzer\nPython")
        reporter = Lambda("secops-reporter\nPython")

    table = Dynamodb("secops-secret-inventory")

    with Cluster("Consumer evidence"):
        trail = Cloudtrail("secops-trail")
        trail_bucket = S3("trail logs")
        athena = Athena("secops-wg")
        glue = Glue("secops_cloudtrail")

    bedrock = Bedrock("Claude on Bedrock\nrotation runbooks")

    with Cluster("Outputs"):
        evidence = S3("evidence bucket\nObject Lock governance")
        hub = SecurityHub("Security Hub\nASFF findings")
        dashboard = S3("dashboard\nstatic site")

    schedule >> scanner
    scanner >> Edge(label="describe/list") >> [secrets, ssm, iam_keys]
    scanner >> table
    scanner >> Edge(label="on success") >> analyzer

    trail >> trail_bucket
    athena >> glue
    analyzer >> Edge(label="GetSecretValue history") >> athena
    athena >> trail_bucket
    analyzer >> table
    analyzer >> Edge(label="strict JSON") >> bedrock
    analyzer >> evidence
    analyzer >> hub
    analyzer >> Edge(label="on success") >> reporter

    reporter >> table
    reporter >> dashboard
