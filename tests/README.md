# Integration tests

Integration tests go here.
I.e. tests that actually connect to an LDAP server.
Offline tests should be kept in the source files.


## Test module layout

Generic test cases go to `client_test_cases` module. And are then called from other
testing modules. This allows reusing code between pooled and non-pooled tests.
