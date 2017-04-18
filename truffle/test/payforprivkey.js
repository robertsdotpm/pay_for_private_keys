var PayForPrivKey = artifacts.require("./PayForPrivKey.sol");

var pub_key_addr = "0x6a46c63617f3aafc87bd826a86a8808ee42dcaac";


var c = null;
var account_one = null;

contract('PayForPrivKey', function(accounts) {
  it("should assert true", function(done) {
    var conference = PayForPrivKey.at(PayForPrivKey.address);
    assert.isTrue(true);
    done();   // stops tests at this point
  });
});

contract('PayForPrivKey', function(accounts) {

  it("should equal the right address", function() {
	 account_one = accounts[0];
	 console.log(account_one);
	 
	 //var c = PayForPrivKey.at(PayForPrivKey.address);
	  var instance = null;
	return PayForPrivKey.new(pub_key_addr, {from: accounts[0], value: web3.toWei(10, 'ether')}).then(
		function(r){
			instance = r;

			return instance.CommitSolutionHash("0x7b5d2de56fdf3218ec89c33bd38fcd6cc4fb6225056ed754ad36b26433db92f4");
	}).then(function(result) {
		console.log(result);
		
		return instance.get_commit_no.call().then(function(index) {
		
			return instance.ProvePrivKey( "0x6d255fc3390ee6b41191da315958b7d6a1e5b17904cc7683558f98acc57977b4", 27, "0xebd664b5f5a6985b36513ec8c9d820d64f588e254e83b31097e370e660049bb5", "0x04b93903c9a0dae40e7146218486282ac5d001302e791ff5455e2695c92255eb", "0x4da432f1ecd4c0ac028ebde3a3f78510a21d54087b161590a63080d33b702b8d", "0x465532fb578613446c707299f71a6d2b68ba87344f14d71207d60b3b3ce02f52", "0xcfd31d218dccc9b553458f1b6c4ace40dada01f7", 0
).then(function(result) {
					//assert.equal(result, true, "Struct not set :("); 
					//console.log(result)
					
					return instance.get_solution.call().then(function(result) {
						console.log(result);
					});
		});
		
	});
		
    }).then(function(result) {
      //assert.equal(result.valueOf(), address, "address wasn't equal");
    });
    
    
    
	});
  
});
