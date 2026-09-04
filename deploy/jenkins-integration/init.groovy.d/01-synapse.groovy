import hudson.model.FreeStyleProject
import hudson.model.InvisibleAction
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins
import jenkins.security.ApiTokenProperty
import jenkins.util.Timer
import org.kohsuke.stapler.export.Exported
import org.kohsuke.stapler.export.ExportedBean

import java.util.concurrent.TimeUnit

@ExportedBean
class SynapseRevisionAction extends InvisibleAction implements Serializable {
  String revision
  String branchName

  @Exported(name = 'lastBuiltRevision')
  Map<String, Object> getLastBuiltRevision() {
    [SHA1: revision, branch: [[SHA1: revision, name: branchName]]]
  }
}

def instance = Jenkins.get()
def realm = new HudsonPrivateSecurityRealm(false)
def user = realm.createAccount('synapse', System.getenv('JENKINS_TEST_PASSWORD'))
def authorizationStrategy = new FullControlOnceLoggedInAuthorizationStrategy()
authorizationStrategy.setAllowAnonymousRead(false)
instance.setSecurityRealm(realm)
instance.setAuthorizationStrategy(authorizationStrategy)
instance.setSystemMessage('Synapse integration test fixture')

if (instance.getItem('synapse-smoke') == null) {
  def job = instance.createProject(FreeStyleProject, 'synapse-smoke')
  job.setDescription('Core-only freestyle job used by the Synapse Jenkins adapter smoke test.')
  job.save()
}

def job = instance.getItem('synapse-smoke')
Timer.get().schedule({
  if (job.getLastBuild() == null) {
    def build = job.scheduleBuild2(0).get()
    build.addAction(new SynapseRevisionAction(
      revision: '0123456789abcdef0123456789abcdef01234567',
      branchName: 'refs/heads/main',
    ))
  }
} as Runnable, 1, TimeUnit.SECONDS)

def token = user.getProperty(ApiTokenProperty).tokenStore.generateNewToken('synapse-e2e').plainValue
user.save()
def tokenFile = new File(instance.rootDir, 'secrets/synapse-api-token')
tokenFile.parentFile.mkdirs()
tokenFile.text = token
tokenFile.setReadable(false, false)
tokenFile.setReadable(true, true)
tokenFile.setWritable(false, false)
tokenFile.setWritable(true, true)
instance.save()
