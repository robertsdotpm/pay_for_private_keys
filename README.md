# pay_for_private_keys
Create contracts in Ethereum to atomically pay someone for a private key.

Details: http://roberts.pm/pay_for_private_keys

Todo list:
* Add refund code to solidity contract to avoid a blackmail attack. It should be impossible to submit new hashes or claim payments after a certain block count, after which point a destroy function can be unlocked.
* Increase the min block count for valid hashes. It's currently zero.
* Fix the Python code to not use fixed indexes for solution hashes and update the docs.
* Might want to make the code more flexible so that outside accounts can send ether to it and the code can reactively withdraw it for a correct solution. So multiple parties can participate. Use a withdraw pattern.
* Create a storage contract example.
* Create good docs for this. Update the current code.
