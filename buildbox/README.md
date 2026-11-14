# Deployment toolbox configuration

CI loads `variables.sh` from the runner credentials path. The file must define `deploy_repository` and `deploy_revision`. Set `deploy_revision` to the lowercase, full 40- or 64-character object ID of the deployment-tool commit approved for the release. Branch names, tags, abbreviated object IDs, and a missing value are rejected.

To update the toolbox, review the deployment repository change and then update `deploy_revision` in the protected runner configuration. Every job fetches that exact commit into a fresh repository, verifies the fetched object, checks out a clean detached worktree, and records the object ID in the CI log. The deployment channels and the `deploy-$tag.sh` signing arguments remain unchanged.

