package com.securebank.labs.a06;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.securebank.domain.Account;
import com.securebank.domain.Transfer;
import com.securebank.domain.repo.AccountRepository;
import com.securebank.domain.repo.TransferRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * <strong>LAB 14 (A06 — Insecure Design): negative transfer amounts.</strong>
 *
 * <p>The transfer amount is never validated as positive. A negative amount
 * is applied as-is to both accounts, so the same negative value is added to
 * the sender <em>and</em> the recipient — both balances shrink and the total
 * money in the system changes, which is the invariant that must never
 * break.
 *
 * <p>This is an insecure <em>design</em> flaw rather than an implementation
 * bug: the check was never part of the design. The endpoint is not
 * injectable and the arithmetic is correct — the arithmetic is simply being
 * handed a value the design never considered.
 */
@Service
public class TransferService {

    private final TransferRepository transfers;
    private final AccountRepository accounts;

    public TransferService(TransferRepository transfers, AccountRepository accounts) {
        this.transfers = transfers;
        this.accounts = accounts;
    }

    /**
     * Move money between two accounts.
     *
     * <p><strong>LAB 14 (VULNERABLE):</strong> the amount is applied without
     * any validation.
     */
    @Transactional
    public Transfer send(Long fromAccountId, Long toAccountId, BigDecimal amount,
                         String note, Long callerUserId) {
        Account from = accounts.findById(fromAccountId)
                .orElseThrow(() -> new TransferException("No account with id " + fromAccountId));
        Account to = accounts.findById(toAccountId)
                .orElseThrow(() -> new TransferException("No account with id " + toAccountId));

        from.setBalance(from.getBalance().add(amount));
        to.setBalance(to.getBalance().add(amount));
        accounts.save(from);
        accounts.save(to);

        Transfer transfer = new Transfer();
        transfer.setFromAccountId(fromAccountId);
        transfer.setToAccountId(toAccountId);
        transfer.setAmount(amount);
        transfer.setNote(note);
        transfer.setRemark(note);
        transfer.setStatus("completed");
        transfer.setCreatedBy(callerUserId);
        transfer.setCreatedAt(Instant.now());
        return transfers.save(transfer);
    }

    /** The transfers visible to a user (their own accounts, both directions). */
    @Transactional(readOnly = true)
    public List<Transfer> visibleTo(Long userId) {
        List<Account> mine = accounts.findByOwnerId(userId);
        if (mine.isEmpty()) {
            return List.of();
        }
        List<Transfer> out = new java.util.ArrayList<>();
        for (Account account : mine) {
            out.addAll(transfers.findByFromAccountId(account.getId()));
            out.addAll(transfers.findByToAccountId(account.getId()));
        }
        return out.stream()
                .distinct()
                .sorted((a, b) -> Long.compare(b.getId(), a.getId()))
                .toList();
    }

    /** A compact view of a transfer, for the UI. */
    public static Map<String, Object> view(Transfer transfer) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("id", transfer.getId());
        body.put("from_account_id", transfer.getFromAccountId());
        body.put("to_account_id", transfer.getToAccountId());
        body.put("amount", transfer.getAmount());
        body.put("note", transfer.getNote());
        body.put("remark", transfer.getRemark());
        body.put("status", transfer.getStatus());
        body.put("created_at", transfer.getCreatedAt());
        return body;
    }

    /** Thrown when a transfer is rejected. */
    public static class TransferException extends RuntimeException {
        public TransferException(String message) {
            super(message);
        }
    }
}
