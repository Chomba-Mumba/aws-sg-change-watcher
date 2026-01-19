resource "aws_cloudtrail" "ec2_events" {
    depends_on = [ data.aws_iam_policy_document.trail_policy ]

    name = "ec2-trail"
    s3_bucket_name = aws_s3_bucket.ec2_trail_bucket.id
    include_global_service_events = true

}
// TODO - filter for SG events
resource "aws_s3_bucket" "ec2_trail_bucket" {
    bucket = "ec2-trail-bucket"
    force_destroy = true
}