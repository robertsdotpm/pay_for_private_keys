var PayForPrivKey = artifacts.require("./PayForPrivKey.sol");

module.exports = function(deployer) {
  deployer.deploy(PayForPrivKey, "0x27f010a8c909d270b3bb192a3558eb164a1ac663");
};

