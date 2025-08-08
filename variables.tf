variable "namespace" {
  description   = "phpipam"
  type          = string
}

variable "subnet_ids" {
  description   = "10.0.0.0/16"
  type          = list(string)
}

variable "vpc_id" {
  description   = "vpc-05197ea4b21acf1e0"
  type          = string
}

variable "app_name"{
  description   = "phpipam"
  type          = string
  default       = "node-red"
}