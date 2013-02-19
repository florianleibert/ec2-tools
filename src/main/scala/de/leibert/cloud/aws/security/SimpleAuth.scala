package de.leibert.cloud.aws.security

import org.clapper.argot.{ArgotUsageException, ArgotParser}
import org.clapper.argot.ArgotConverters._
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.auth.BasicAWSCredentials

/**
 * @author Florian Leibert (flo@leibert.de)
 */
object SimpleAuth {

  //Environment variables to access S3
  val accessKeyString = "AWS_ACCESS_KEY_ID"
  val secretKeyString = "AWS_SECRET_ACCESS_KEY"

  val parser = new ArgotParser("ec2-security-cli  ", preUsage = Some("Version 1.0, by Flo"))

  //Command line parser options
  val group = parser.option[String](List("group"), "sg-XXXXXXX", "the security group identifier string")
  val fromPort = parser.option[Int](List("from_port"), "int", "the lower bound")
  val toPort = parser.option[Int](List("to_port"), "int", "the upper bound")
  val protocol = parser.option[String](List("protocol"), "TCP", "the protocol, e.g. TCP or UDP")
  val ipRange = parser.option[String](List("ip_range"), "0.0.0.0/0", "the source range")

  def runApplication {
    import scala.collection.JavaConversions._

    val env = System.getenv()
    //Ensure ENV vars for accessing AWS credentials are set
    assert(env.contains(accessKeyString) && env(accessKeyString).length > 0,
           "The environment variable %s is either not set or blank".format(accessKeyString))
    assert(env.contains(secretKeyString) && env(secretKeyString).length > 0,
           "The environment variable %s is either not set or blank".format(secretKeyString))

    val accessKey = env.get(accessKeyString)
    val secretKey = env.get(secretKeyString)
    val client = new AmazonEC2Client(new BasicAWSCredentials(accessKey, secretKey))
    println("Checking group: '%s', protocol: '%s', ports: '%d-%d' range '%s'"
              .format(group.value.get, protocol.value.get, fromPort.value.get, toPort.value.get, ipRange.value.get))
    if (!SecurityGroupUtils.exists(
        client, group.value.get, protocol.value.get, ipRange.value.get, fromPort.value.get, toPort.value.get)) {

      SecurityGroupUtils.authorize(
        client, group.value.get, protocol.value.get, ipRange.value.get, fromPort.value.get, toPort.value.get)
      println("Authorized: '%s' -> %s:%d-%d ingress from %s"
                .format(group.value.get, protocol.value.get, fromPort.value.get, toPort.value.get, ipRange.value.get))
    } else {
      println("Not authorizing, rule already exists!")
    }
  }

  def main(args: Array[String]) = {
    try {
      parser.parse(args)
      runApplication
    }
    catch {
      case e: ArgotUsageException => println(e.message)
    }
  }
}
