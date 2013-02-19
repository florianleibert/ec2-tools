package de.leibert.cloud.aws.security

import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.model._
import junit.framework.TestCase
import junit.framework.Assert._
import org.mockito.Mockito._
import org.mockito.Matchers._

/**
 * @author Florian Leibert (flo@leibert.de)
 */
class SecurityGroupUtilsTest extends TestCase("app") {

  def makeSecurityGroupResponse(gid : String, range : String, fromPort : Int, toPort : Int) = {
    val g = new SecurityGroup()
    g.setDescription(gid)

    val ipPermission = new IpPermission
    ipPermission.setFromPort(fromPort)
    ipPermission.setToPort(toPort)
    ipPermission.setIpProtocol("TCP")
    ipPermission.getIpRanges.add(range)
    g.getIpPermissions.add(ipPermission)
    val res = new DescribeSecurityGroupsResult
    res.getSecurityGroups.add(g)
    res
  }

  def testMatchingSecurityGroup() = {
    val mockEC2 = mock(classOf[AmazonEC2])
    val gid = "sg-XXXXXX"
    val range = "0.0.0.0/0"
    val fromPort = 0
    val toPort = 3300
    val proto = "TCP"

    when(mockEC2.describeSecurityGroups(any(classOf[DescribeSecurityGroupsRequest]))).thenReturn(makeSecurityGroupResponse(gid,range,fromPort,toPort))
    assertTrue("Security group should be matched properly",
               SecurityGroupUtils.exists(mockEC2, gid, proto, range, fromPort, toPort))
  }
}
