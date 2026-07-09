resource "aws_instance" "web" {
  ami = "ami-0aba19e56f3eaec05"
  instance_type = "t3.micro"

}
