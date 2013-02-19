package de.leibert.cloud.aws.security

import scala.Array

import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.ec2.{AmazonEC2, AmazonEC2Client}
import com.amazonaws.services.ec2.model.{DescribeSecurityGroupsRequest, IpPermission, AuthorizeSecurityGroupIngressRequest}
import com.amazonaws.services.s3.{AmazonS3Client, AmazonS3}
import org.clapper.argot.{ArgotUsageException, ArgotParser}
import org.clapper.argot.ArgotConverters._

/**
 * Simple security for ec2.
 * @author Florian Leibert (flo@leibert.de)
 */
object SecurityGroupUtils {


  //Environment variables to access S3
  val accessKeyString = "AWS_ACCESS_KEY_ID"
  val secretKeyString = "AWS_SECRET_ACCESS_KEY"

  def makeS3Client(accessKey: String, secretKey: String): AmazonS3 =
    return new AmazonS3Client(new BasicAWSCredentials(accessKey, secretKey))

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
    authorize(client, group.value.get, protocol.value.get, ipRange.value.get, fromPort.value.get, toPort.value.get)
  }

  def exists(ec2: AmazonEC2, groupId: String, proto: String, ipRange: String, fromPort: Int, toPort: Int)
    : Boolean = {
    val descRequest = new DescribeSecurityGroupsRequest()
    descRequest.getGroupNames.add(groupId)

    val groups = ec2.describeSecurityGroups(descRequest).getSecurityGroups
    assert(groups.size == 1, "Security group not found or matched more than one group.")
    val group = groups.get(0)
    val permissions = group.getIpPermissions
    import scala.collection.JavaConversions._

    return permissions.filter({x => (x.getToPort == toPort &&
                                     x.getIpProtocol == proto &&
                                     x.getIpRanges.size == 1 &&
                                     x.getIpRanges.get(0) == ipRange &&
                                     x.getFromPort == fromPort &&
                                     x.getToPort == toPort)}).size == 1
  }

  def authorize(ec2: AmazonEC2, groupId: String, proto: String, ipRange: String, fromPort: Int, toPort: Int) {
    val ingressRequest = new AuthorizeSecurityGroupIngressRequest()
    ingressRequest.setGroupId(groupId)

    val ipPermission = new IpPermission()
    ipPermission.setIpProtocol(proto)
    ipPermission.setFromPort(fromPort)
    ipPermission.setToPort(toPort)
    ipPermission.getIpRanges.add(ipRange)
    ingressRequest.getIpPermissions.add(ipPermission)

    ec2.authorizeSecurityGroupIngress(ingressRequest)
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
