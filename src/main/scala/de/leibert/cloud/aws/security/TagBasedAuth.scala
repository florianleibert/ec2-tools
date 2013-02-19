package de.leibert.cloud.aws.security

import com.amazonaws.services.ec2.{AmazonEC2, AmazonEC2Client}
import com.amazonaws.auth.BasicAWSCredentials
import org.clapper.argot.{ArgotUsageException, ArgotParser}
import org.clapper.argot.ArgotConverters._
import collection.mutable

/**
 * @author Florian Leibert (flo@leibert.de)
 */
object TagBasedAuth {

  //Environment variables to access S3
  val accessKeyString = "AWS_ACCESS_KEY_ID"
  val secretKeyString = "AWS_SECRET_ACCESS_KEY"

  val parser = new ArgotParser("ec2-security-cli  ", preUsage = Some("Version 1.0, by Flo"))

  //Command line parser options
  val group = parser.option[String](List("group"), "sg-XXXXXXX", "the security group identifier string")
  val fromPort = parser.option[Int](List("from_port"), "int", "the lower bound")
  val toPort = parser.option[Int](List("to_port"), "int", "the upper bound")
  val protocol = parser.option[String](List("protocol"), "TCP", "the protocol, e.g. TCP or UDP")
  val tagName =  parser.option[String](List("tag_name"), "name", "the key portion of the tag")
  val tagFilter = parser.option[String](List("tag_filter"), "mesos-foo.*", "a regex filter for the tag value")

  /**
   * Retrieves tuples of of instance_id, public_ip of all matching instances for a given tag_name and a filter pattern.
   * @param ec2
   * @param tagName
   * @param tagFilter
   * @return tuples of (instance_id, public_ip)
   */
  def describeInstances(ec2: AmazonEC2, tagName: String, tagFilter: String) : Traversable[(String, String)] = {
    val regex = (""""""+tagFilter).r
    import scala.collection.JavaConversions._
    val instances = ec2.describeInstances.getReservations.flatMap(x => x.getInstances)
    val matchingInstances : mutable.Buffer[(String, String, String, String)] = instances.flatMap(y => y.getTags
      .map(x => (x.getKey, x.getValue, y.getInstanceId, y.getPublicIpAddress)))
      .filter(p  => p._1.toLowerCase == tagName && regex.findFirstIn(p._2.toLowerCase).nonEmpty)
    matchingInstances.map({ x => (x._3, x._4)})
  }

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
    val instances = describeInstances(client, tagName.value.get, tagFilter.value.get)

    def checkAndAuthorize(ip : String) = {
      val ipRange = "%s/32".format(ip)
      if (!SecurityGroupUtils.exists(
        client, group.value.get, protocol.value.get, ipRange, fromPort.value.get, toPort.value.get)) {
        SecurityGroupUtils.authorize(
          client, group.value.get, protocol.value.get, ipRange, fromPort.value.get, toPort.value.get)
      }
    }

    instances.foreach(x => checkAndAuthorize(x._2))
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
