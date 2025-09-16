# v0.1.1 - 2025-09-16

* Fixes a significant bug that could cause deadlocks due to the writer not
  being returned to the state
* Fixes another potential deadlock issue by making sure the different locks
  are always acquired in a consistent order

# v0.1 - 2025-09-16

Initial release.
