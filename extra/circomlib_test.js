const circomlib = require("circomlibjs");

(async () => {
    const poseidon = await circomlib.buildPoseidon();
    const hash = poseidon([1n, 2n]);     
    console.log(poseidon.F.toObject(hash)); // decimal
    console.log(poseidon.F.toString(hash, 16)); // hex
})();
