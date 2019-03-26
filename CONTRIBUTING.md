# Contributing to IOTA.MAM

Thanks for your interest in this project!

You can contribute bugfixes and new features by sending pull requests through GitHub.

## Contributing a change

1. [Fork the repository on GitHub](https://github.com/gallegogt/iota.mam.rust/fork)
2. Clone the forked repository onto your computer: ``` git clone https://github.com/<your username>/iota.mam.rust.git ```
3. Create a new branch from the latest ```develop``` branch with ```git checkout -b YOUR_BRANCH_NAME origin/develop```
4. Make your changes
5. If developing a new feature, make sure to include unit tests.
6. Ensure that all new and existing tests pass.
7. Commit the changes into the branch: ``` git commit -s ``` Make sure that your commit message is meaningful and describes your changes correctly.
8. If you have a lot of commits for the change, squash them into a single / few commits.
9. Push the changes in your branch to your forked repository.
10. Finally, go to [https://github.com/eclipse/iota.mam.rust](https://github.com/eclipse/iota.mam.rust) and create a pull request from your "YOUR_BRANCH_NAME" branch to the ```develop``` one to request review and merge of the commits in your pushed branch.


What happens next depends on the content of the patch. If it is 100% authored
by the contributor and is less than 1000 lines (and meets the needs of the
project), then it can be pulled into the main repository. If not, more steps
are required.


Create a new bug:
-----------------
#
Be sure to search for existing bugs before you create another one. Remember that contributions are always welcome!

- [Create new IOTA.MAM bug](https://github.com/eclipse/iota.mam.rust/issues/new)