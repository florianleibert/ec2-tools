package de.leibert.cloud.aws.security

import junit.framework._

/**
 * @author Florian Leibert (flo@leibert.de)
 */
object AllTests {
  def suite: Test = {
    val suite = new TestSuite(classOf[SecurityGroupUtilsTest])
    suite
  }

  def main(args : Array[String]) {
    junit.textui.TestRunner.run(suite)
  }
}