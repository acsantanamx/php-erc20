<?php
/**
 * User: Lessmore92
 * Date: 11/23/2020
 * Time: 2:09 AM
 * last update by ACSR
 * date: 07/07/2025
 */

namespace Lessmore92\Ethereum\Foundation\Transaction;

use kornrunner\Ethereum\Transaction as BaseTransaction;
use Lessmore92\Ethereum\Foundation\Eth;

class Transaction {
    private $transaction;
    private $eth;
    private $chainId = 0;

    public function __construct(BaseTransaction $transaction, Eth $eth = null, int $chainId = 0) {
        $this->transaction = $transaction;
        $this->eth         = $eth;
        $this->chainId     = $chainId;
    }

    public function sign($privateKey) {
        $privateKey = str_replace('0x', '', $privateKey);
        return new SignedTransaction('0x' . $this->transaction->getRaw($privateKey, $this->chainId), $this->eth);
    }
}

