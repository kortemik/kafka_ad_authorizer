### Notes ###
This repo is forked from git@github.com:opencore/kafka_ad_authorizer.git

ComplexAclAuthorizer.scala is almost the same as SimpleAclAuthorizer.scala on following commit:
```
commit c0518aa65f25317eca0c1da4d350f549d35b8536 (HEAD, tag: 1.0.1-rc2, tag: 1.0.1)
```

Diff:
```
iff --git a/src/main/scala/com/opencore/kafka/ComplexAclAuthorizer.scala b/src/main/scala/com/opencore/kafka/ComplexAclAuthorizer.scala
index 91f13ab..3c94964 100644
--- a/src/main/scala/com/opencore/kafka/ComplexAclAuthorizer.scala
+++ b/src/main/scala/com/opencore/kafka/ComplexAclAuthorizer.scala
@@ -1,39 +1,38 @@
 /**
-  * Licensed to the Apache Software Foundation (ASF) under one or more
-  * contributor license agreements.  See the NOTICE file distributed with
-  * this work for additional information regarding copyright ownership.
-  * The ASF licenses this file to You under the Apache License, Version 2.0
-  * (the "License"); you may not use this file except in compliance with
-  * the License.  You may obtain a copy of the License at
-  *
-  * http://www.apache.org/licenses/LICENSE-2.0
-  *
-  * Unless required by applicable law or agreed to in writing, software
-  * distributed under the License is distributed on an "AS IS" BASIS,
-  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  * See the License for the specific language governing permissions and
-  * limitations under the License.
-  */
-package com.opencore.kafka
+ * Licensed to the Apache Software Foundation (ASF) under one or more
+ * contributor license agreements.  See the NOTICE file distributed with
+ * this work for additional information regarding copyright ownership.
+ * The ASF licenses this file to You under the Apache License, Version 2.0
+ * (the "License"); you may not use this file except in compliance with
+ * the License.  You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package kafka.security.auth
 
 import java.util
 import java.util.concurrent.locks.ReentrantReadWriteLock
-
-import com.opencore.kafka.ComplexAclAuthorizer.VersionedAcls
 import kafka.common.{NotificationHandler, ZkNodeChangeNotificationListener}
+
 import kafka.network.RequestChannel.Session
-import kafka.security.auth._
+import kafka.security.auth.SimpleAclAuthorizer.VersionedAcls
 import kafka.server.KafkaConfig
 import kafka.utils.CoreUtils.{inReadLock, inWriteLock}
 import kafka.utils._
-import org.I0Itec.zkclient.exception.{ZkNoNodeException, ZkNodeExistsException}
+import org.I0Itec.zkclient.exception.{ZkNodeExistsException, ZkNoNodeException}
 import org.apache.kafka.common.security.auth.KafkaPrincipal
+import scala.collection.JavaConverters._
 import org.apache.log4j.Logger
 
-import scala.collection.JavaConverters._
 import scala.util.Random
 
-object ComplexAclAuthorizer {
+object SimpleAclAuthorizer {
   //optional override zookeeper cluster configuration where acls will be stored, if not specified acls will be stored in
   //same zookeeper where all other kafka broker info is stored.
   val ZkUrlProp = "authorizer.zookeeper.url"
@@ -46,16 +45,16 @@ object ComplexAclAuthorizer {
   val AllowEveryoneIfNoAclIsFoundProp = "allow.everyone.if.no.acl.found"
 
   /**
-    * The root acl storage node. Under this node there will be one child node per resource type (Topic, Cluster, Group).
-    * under each resourceType there will be a unique child for each resource instance and the data for that child will contain
-    * list of its acls as a json object. Following gives an example:
-    *
-    * <pre>
-    * /kafka-acl/Topic/topic-1 => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
-    * /kafka-acl/Cluster/kafka-cluster => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
-    * /kafka-acl/Group/group-1 => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
-    * </pre>
-    */
+   * The root acl storage node. Under this node there will be one child node per resource type (Topic, Cluster, Group).
+   * under each resourceType there will be a unique child for each resource instance and the data for that child will contain
+   * list of its acls as a json object. Following gives an example:
+   *
+   * <pre>
+   * /kafka-acl/Topic/topic-1 => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
+   * /kafka-acl/Cluster/kafka-cluster => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
+   * /kafka-acl/Group/group-1 => {"version": 1, "acls": [ { "host":"host1", "permissionType": "Allow","operation": "Read","principal": "User:alice"}]}
+   * </pre>
+   */
   val AclZkPath = ZkUtils.KafkaAclPath
 
   //notification node which gets updated with the resource name when acl on a resource is changed.
@@ -65,10 +64,9 @@ object ComplexAclAuthorizer {
   val AclChangedPrefix = "acl_changes_"
 
   private case class VersionedAcls(acls: Set[Acl], zkVersion: Int)
-
 }
 
-class ComplexAclAuthorizer extends Authorizer with Logging {
+class SimpleAclAuthorizer extends Authorizer with Logging {
   private val authorizerLogger = Logger.getLogger("kafka.authorizer.logger")
   private var superUsers = Set.empty[KafkaPrincipal]
   private var shouldAllowEveryoneIfNoAclIsFound = false
@@ -80,43 +78,43 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
 
   // The maximum number of times we should try to update the resource acls in zookeeper before failing;
   // This should never occur, but is a safeguard just in case.
-  var maxUpdateRetries = 10
+  protected[auth] var maxUpdateRetries = 10
 
   private val retryBackoffMs = 100
   private val retryBackoffJitterMs = 50
 
   /**
-    * Guaranteed to be called before any authorize call is made.
-    */
+   * Guaranteed to be called before any authorize call is made.
+   */
   override def configure(javaConfigs: util.Map[String, _]) {
     val configs = javaConfigs.asScala
     val props = new java.util.Properties()
     configs.foreach { case (key, value) => props.put(key, value.toString) }
 
-    superUsers = configs.get(ComplexAclAuthorizer.SuperUsersProp).collect {
+    superUsers = configs.get(SimpleAclAuthorizer.SuperUsersProp).collect {
       case str: String if str.nonEmpty => str.split(";").map(s => KafkaPrincipal.fromString(s.trim)).toSet
     }.getOrElse(Set.empty[KafkaPrincipal])
 
-    shouldAllowEveryoneIfNoAclIsFound = configs.get(ComplexAclAuthorizer.AllowEveryoneIfNoAclIsFoundProp).exists(_.toString.toBoolean)
+    shouldAllowEveryoneIfNoAclIsFound = configs.get(SimpleAclAuthorizer.AllowEveryoneIfNoAclIsFoundProp).exists(_.toString.toBoolean)
 
     // Use `KafkaConfig` in order to get the default ZK config values if not present in `javaConfigs`. Note that this
     // means that `KafkaConfig.zkConnect` must always be set by the user (even if `SimpleAclAuthorizer.ZkUrlProp` is also
     // set).
     val kafkaConfig = KafkaConfig.fromProps(props, doLog = false)
-    val zkUrl = configs.get(ComplexAclAuthorizer.ZkUrlProp).map(_.toString).getOrElse(kafkaConfig.zkConnect)
-    val zkConnectionTimeoutMs = configs.get(ComplexAclAuthorizer.ZkConnectionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkConnectionTimeoutMs)
-    val zkSessionTimeOutMs = configs.get(ComplexAclAuthorizer.ZkSessionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkSessionTimeoutMs)
+    val zkUrl = configs.get(SimpleAclAuthorizer.ZkUrlProp).map(_.toString).getOrElse(kafkaConfig.zkConnect)
+    val zkConnectionTimeoutMs = configs.get(SimpleAclAuthorizer.ZkConnectionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkConnectionTimeoutMs)
+    val zkSessionTimeOutMs = configs.get(SimpleAclAuthorizer.ZkSessionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkSessionTimeoutMs)
 
     zkUtils = ZkUtils(zkUrl,
-      sessionTimeout = zkSessionTimeOutMs,
-      connectionTimeout = zkConnectionTimeoutMs,
-      kafkaConfig.zkEnableSecureAcls)
-    zkUtils.makeSurePersistentPathExists(ComplexAclAuthorizer.AclZkPath)
+                      sessionTimeout = zkSessionTimeOutMs,
+                      connectionTimeout = zkConnectionTimeoutMs,
+                      kafkaConfig.zkEnableSecureAcls)
+    zkUtils.makeSurePersistentPathExists(SimpleAclAuthorizer.AclZkPath)
 
     loadCache()
 
-    zkUtils.makeSurePersistentPathExists(ComplexAclAuthorizer.AclChangedZkPath)
-    aclChangeListener = new ZkNodeChangeNotificationListener(zkUtils, ComplexAclAuthorizer.AclChangedZkPath, ComplexAclAuthorizer.AclChangedPrefix, AclChangedNotificationHandler)
+    zkUtils.makeSurePersistentPathExists(SimpleAclAuthorizer.AclChangedZkPath)
+    aclChangeListener = new ZkNodeChangeNotificationListener(zkUtils, SimpleAclAuthorizer.AclChangedZkPath, SimpleAclAuthorizer.AclChangedPrefix, AclChangedNotificationHandler)
     aclChangeListener.init()
   }
 
@@ -156,57 +154,29 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
   }
 
   def isSuperUser(operation: Operation, resource: Resource, principal: KafkaPrincipal, host: String): Boolean = {
-    // Convert to KafkaPrincipal if we get a ComplexPrincipal
-    val effectivePrincipal = if (principal.isInstanceOf[ComplexKafkaPrincipal])
-      new KafkaPrincipal(principal.getPrincipalType, principal.getName)
-    else
-      principal
-
-    if (superUsers.contains(effectivePrincipal)) {
+    if (superUsers.contains(principal)) {
       authorizerLogger.debug(s"principal = $principal is a super user, allowing operation without checking acls.")
       true
     } else false
   }
 
-  private def aclMatch(operations: Operation, resource: Resource, principal: KafkaPrincipal,
-                       host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {
-    // Build a list of all Principals for this ComplexPrincipal
-    var allPrincipals = List[KafkaPrincipal]()
-
-    if (principal.isInstanceOf[ComplexKafkaPrincipal]) {
-      // For a Complexprincipal use the wrapped list
-      allPrincipals = principal.asInstanceOf[ComplexKafkaPrincipal].getPrincipalList.asScala.toList
-    } else {
-      // For a KafkaPrincipal simply create a list with only that principal
-      allPrincipals ::= new KafkaPrincipal(principal.getPrincipalType, principal.getName)
-    }
-
-    // Match principals against ACLs
-    allPrincipals
-      .map(p => singleAclMatch(operations, resource, p, host, permissionType, acls))
-      .foldLeft(false)(_ || _)
-  }
-
-  private def singleAclMatch(operations: Operation, resource: Resource, principal: KafkaPrincipal, host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {
-    acls.find {
-      acl =>
-        acl.permissionType == permissionType &&
-          (acl.principal == principal || acl.principal == Acl.WildCardPrincipal) &&
-          (operations == acl.operation || acl.operation == All) &&
-          (acl.host == host || acl.host == Acl.WildCardHost)
-    }.exists {
-      acl =>
-        authorizerLogger.debug(s"operation = $operations on resource = $resource from host = $host is $permissionType based on acl = $acl")
-        true
+  private def aclMatch(operations: Operation, resource: Resource, principal: KafkaPrincipal, host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {
+    acls.find { acl =>
+      acl.permissionType == permissionType &&
+        (acl.principal == principal || acl.principal == Acl.WildCardPrincipal) &&
+        (operations == acl.operation || acl.operation == All) &&
+        (acl.host == host || acl.host == Acl.WildCardHost)
+    }.exists { acl =>
+      authorizerLogger.debug(s"operation = $operations on resource = $resource from host = $host is $permissionType based on acl = $acl")
+      true
     }
   }
 
   override def addAcls(acls: Set[Acl], resource: Resource) {
     if (acls != null && acls.nonEmpty) {
       inWriteLock(lock) {
-        updateResourceAcls(resource) {
-          currentAcls =>
-            currentAcls ++ acls
+        updateResourceAcls(resource) { currentAcls =>
+          currentAcls ++ acls
         }
       }
     }
@@ -214,9 +184,8 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
 
   override def removeAcls(aclsTobeRemoved: Set[Acl], resource: Resource): Boolean = {
     inWriteLock(lock) {
-      updateResourceAcls(resource) {
-        currentAcls =>
-          currentAcls -- aclsTobeRemoved
+      updateResourceAcls(resource) { currentAcls =>
+        currentAcls -- aclsTobeRemoved
       }
     }
   }
@@ -238,12 +207,10 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
 
   override def getAcls(principal: KafkaPrincipal): Map[Resource, Set[Acl]] = {
     inReadLock(lock) {
-      aclCache.mapValues {
-        versionedAcls =>
-          versionedAcls.acls.filter(_.principal == principal)
-      }.filter {
-        case (_, acls) =>
-          acls.nonEmpty
+      aclCache.mapValues { versionedAcls =>
+        versionedAcls.acls.filter(_.principal == principal)
+      }.filter { case (_, acls) =>
+        acls.nonEmpty
       }.toMap
     }
   }
@@ -259,12 +226,12 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
     if (zkUtils != null) zkUtils.close()
   }
 
-  private def loadCache() {
+  private def loadCache()  {
     inWriteLock(lock) {
-      val resourceTypes = zkUtils.getChildren(ComplexAclAuthorizer.AclZkPath)
+      val resourceTypes = zkUtils.getChildren(SimpleAclAuthorizer.AclZkPath)
       for (rType <- resourceTypes) {
         val resourceType = ResourceType.fromString(rType)
-        val resourceTypePath = ComplexAclAuthorizer.AclZkPath + "/" + resourceType.name
+        val resourceTypePath = SimpleAclAuthorizer.AclZkPath + "/" + resourceType.name
         val resourceNames = zkUtils.getChildren(resourceTypePath)
         for (resourceName <- resourceNames) {
           val versionedAcls = getAclsFromZk(Resource(resourceType, resourceName.toString))
@@ -275,7 +242,7 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
   }
 
   def toResourcePath(resource: Resource): String = {
-    ComplexAclAuthorizer.AclZkPath + "/" + resource.resourceType + "/" + resource.name
+    SimpleAclAuthorizer.AclZkPath + "/" + resource.resourceType + "/" + resource.name
   }
 
   private def logAuditMessage(principal: KafkaPrincipal, authorized: Boolean, operation: Operation, resource: Resource, host: String) {
@@ -294,7 +261,7 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
     *
     * Returns a boolean indicating if the content of the ACLs was actually changed.
     *
-    * @param resource   the resource to change ACLs for
+    * @param resource the resource to change ACLs for
     * @param getNewAcls function to transform existing acls to new ACLs
     * @return boolean indicating if a change was made
     */
@@ -314,16 +281,14 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
       val data = Json.encode(Acl.toJsonCompatibleMap(newAcls))
       val (updateSucceeded, updateVersion) =
         if (newAcls.nonEmpty) {
-          updatePath(path, data, currentVersionedAcls.zkVersion)
+         updatePath(path, data, currentVersionedAcls.zkVersion)
         } else {
           trace(s"Deleting path for $resource because it had no ACLs remaining")
           (zkUtils.conditionalDeletePath(path, currentVersionedAcls.zkVersion), 0)
         }
 
       if (!updateSucceeded) {
-        trace(s"Failed to update ACLs for $resource. Used version ${
-          currentVersionedAcls.zkVersion
-        }. Reading data and retrying update.")
+        trace(s"Failed to update ACLs for $resource. Used version ${currentVersionedAcls.zkVersion}. Reading data and retrying update.")
         Thread.sleep(backoffTime)
         currentVersionedAcls = getAclsFromZk(resource)
         retries += 1
@@ -333,15 +298,11 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
       }
     }
 
-    if (!writeComplete)
+    if(!writeComplete)
       throw new IllegalStateException(s"Failed to update ACLs for $resource after trying a maximum of $maxUpdateRetries times")
 
     if (newVersionedAcls.acls != currentVersionedAcls.acls) {
-      debug(s"Updated ACLs for $resource to ${
-        newVersionedAcls.acls
-      } with version ${
-        newVersionedAcls.zkVersion
-      }")
+      debug(s"Updated ACLs for $resource to ${newVersionedAcls.acls} with version ${newVersionedAcls.zkVersion}")
       updateCache(resource, newVersionedAcls)
       updateAclChangedFlag(resource)
       true
@@ -391,7 +352,7 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
   }
 
   private def updateAclChangedFlag(resource: Resource) {
-    zkUtils.createSequentialPersistentPath(ComplexAclAuthorizer.AclChangedZkPath + "/" + ComplexAclAuthorizer.AclChangedPrefix, resource.toString)
+    zkUtils.createSequentialPersistentPath(SimpleAclAuthorizer.AclChangedZkPath + "/" + SimpleAclAuthorizer.AclChangedPrefix, resource.toString)
   }
 
   private def backoffTime = {
@@ -407,5 +368,4 @@ class ComplexAclAuthorizer extends Authorizer with Logging {
       }
     }
   }
-
 }
```
