# Terraform test file

provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "user_data_bucket" {
  bucket = "user-data-storage"
}

resource "aws_db_instance" "user_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  name                 = "userdb"
  username             = "admin"
  password             = "password"
  skip_final_snapshot  = true
}
