/**
 * @name Unpinned tag for 3rd party Action in workflow
 * @description Using a tag for a 3rd party Action that is not pinned to a commit can lead to executing an untrusted Action through a supply chain attack.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision high
 * @id js/actions/unpinned-tag
 * @tags actions
 *       security
 *       experimental
 *       external/cwe/cwe-829
 */

import javascript
import semmle.javascript.Actions

private predicate isUsingSecrets(Actions::Run run) {
    run.getValue().regexpMatch("^echo[^\n\r]*secrets[^\n\r]*$")
}

from Actions::Step step, Actions::Uses uses, Actions::Run run, string repo, Actions::Workflow workflow, string name
where
step.getUses() = uses and
uses.getGitHubRepository() = repo and
isUsingSecrets(run) and
workflow.getJob(_).getStep(_) = step and
(
    workflow.getName() = name
    or
    (not exists(workflow.getName()) and workflow.getFileName() = name)
)
select step, "The run action in step $@ uses '" + repo + "', may leak secrets", step, step.toString()
