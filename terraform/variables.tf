variable manage_sg_file {
    type = string
    description = "path to manage security group binary file zip from tf dir"
    default = "../bin/manage_sg.zip"
}

variable region {
    type = string
    description = "aws region"
    default = "eu-west-2"
}