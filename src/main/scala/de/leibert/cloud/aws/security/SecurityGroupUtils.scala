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

  def exists(ec2: AmazonEC2, groupId: String, proto: String, ipRange: String, fromPort: Int, toPort: Int)
    : Boolean = {
    val descRequest = new DescribeSecurityGroupsRequest()
    descRequest.getGroupIds.add(groupId)

    val groups = ec2.describeSecurityGroups(descRequest).getSecurityGroups
    assert(groups.size == 1, "Security group not found or matched more than one group.")
    val group = groups.get(0)
    val permissions = group.getIpPermissions
    import scala.collection.JavaConversions._

    return permissions.filter({x => (x.getToPort == toPort &&
                                     x.getIpProtocol.toLowerCase == proto.toLowerCase &&
                                     x.getFromPort == fromPort &&
                                     x.getToPort == toPort)})
             .flatMap(_.getIpRanges)
             .filter({x => x == ipRange }).size == 1
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
}
