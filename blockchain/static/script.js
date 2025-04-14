document.addEventListener("DOMContentLoaded", function() {
    // Utility function to render JSON data as a table or formatted text.
    function renderJSONAsTable(data, containerId) {
        const container = document.getElementById(containerId);
        if (!Array.isArray(data)) {
            container.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            return;
        }
        if (data.length === 0) {
            container.innerHTML = "<p>No data found.</p>";
            return;
        }
        const keys = Object.keys(data[0]);
        let table = "<table><thead><tr>";
        keys.forEach(key => {
            table += `<th>${key}</th>`;
        });
        table += "</tr></thead><tbody>";
        data.forEach(row => {
            table += "<tr>";
            keys.forEach(key => {
                table += `<td>${row[key]}</td>`;
            });
            table += "</tr>";
        });
        table += "</tbody></table>";
        container.innerHTML = table;
    }

    // Create Wallet
    document.getElementById("createWalletBtn").addEventListener("click", function() {
        fetch("/create_wallet", { method: "POST" })
        .then(response => response.json())
        .then(data => {
            alert("Wallet Created:\nAddress: " + data.wallet_address + "\nSeed: " + data.seed_phrase);
        })
        .catch(err => console.error(err));
    });

    // List Wallets
    document.getElementById("listWalletsBtn").addEventListener("click", function() {
        fetch("/list_wallets")
        .then(response => response.json())
        .then(data => {
            renderJSONAsTable(data, "walletsOutput");
        })
        .catch(err => console.error(err));
    });

    // Create Transaction
    document.getElementById("transactionForm").addEventListener("submit", function(e) {
        e.preventDefault();
        const sender = document.getElementById("sender").value;
        const recipient = document.getElementById("recipient").value;
        const amount = document.getElementById("amount").value;
        fetch("/create_transaction", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sender, recipient, amount })
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById("transactionOutput").innerText = data.message || data.error;
        })
        .catch(err => console.error(err));
    });

    // Mine Block
    document.getElementById("mineForm").addEventListener("submit", function(e) {
        e.preventDefault();
        const miner_address = document.getElementById("miner_address").value;
        fetch("/mine_block", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ miner_address })
        })
        .then(response => response.json())
        .then(data => {
            let msg = data.message || data.error;
            if(data.block_hash) {
                msg += "\nBlock Hash: " + data.block_hash;
                msg += "\nReward: " + data.reward;
            }
            document.getElementById("mineOutput").innerText = msg;
        })
        .catch(err => console.error(err));
    });

    // Check Wallet Balance
    document.getElementById("balanceForm").addEventListener("submit", function(e) {
        e.preventDefault();
        const wallet_address = document.getElementById("balance_wallet_address").value;
        fetch("/wallet_balance?wallet_address=" + wallet_address)
        .then(response => response.json())
        .then(data => {
            if(data.error) {
                document.getElementById("balanceOutput").innerText = data.error;
            } else {
                document.getElementById("balanceOutput").innerText = "Balance: " + data.balance;
            }
        })
        .catch(err => console.error(err));
    });

    // Validate Blockchain
    document.getElementById("validateBlockchainBtn").addEventListener("click", function() {
        fetch("/validate_blockchain")
        .then(response => response.json())
        .then(data => {
            document.getElementById("validateOutput").innerText = data.message;
        })
        .catch(err => console.error(err));
    });

    // Show Blockchain
    document.getElementById("showBlockchainBtn").addEventListener("click", function() {
        fetch("/show_blockchain")
        .then(response => response.json())
        .then(data => {
            // Pretty-print JSON data
            document.getElementById("blockchainOutput").innerText = JSON.stringify(data, null, 4);
        })
        .catch(err => console.error(err));
    });
});
