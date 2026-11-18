package com.securebank.labs.a06;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.securebank.core.LabToggles;
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
 *
 * <p><strong>FIX:</strong> delete the vulnerable branch. The intended end
 * state validates that the amount is positive, that the accounts are
 * distinct, that the sender has the funds, and that the currency matches.
 */
@Service
public class TransferService {

    private final TransferRepository transfers;
    private final AccountRepository accounts;
    private final LabToggles labs;

    public TransferService(TransferRepository transfers, AccountRepository accounts, LabToggles labs) {
        this.transfers = transfers;
        this.accounts = accounts;
        this.labs = labs;
    }

    /**
     * Move money between two accounts.
     *
     * <p><strong>LAB 14 (VULNERABLE):</strong> the amount is applied without
     * any validation.
     *
     * <p><strong>FIX:</strong> delete this branch and use
     * {@link #sendFixed(Long, Long, BigDecimal, String, Long)}.
     */
    @Transactional
    public Transfer send(Long fromAccountId, Long toAccountId, BigDecimal amount,
                         String note, Long callerUserId) {
        if (labs.isEnabled("negativetransfer")) {
            // LAB 14 (VULNERABLE): no validation of the amount, the accounts
            // or the balance. A negative amount is added to BOTH sides, so
            // both balances shrink and the total money in the system
            // changes.
            //
            // FIX: use sendFixed(...) below.
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

        // ---- FIX (the intended final state) ----
        return sendFixed(fromAccountId, toAccountId, amount, note, callerUserId);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>The amount must be positive, the two accounts must differ, the
     * sender must have the funds, and both accounts must use the same
     * currency.
     */
    @Transactional
    public Transfer sendFixed(Long fromAccountId, Long toAccountId, BigDecimal amount,
                              String note, Long callerUserId) {
        if (amount == null) {
            throw new TransferException("Amount is required");
        }
        if (amount.signum() <= 0) {
            throw new TransferException("Amount must be positive");
        }
        if (Objects.equals(fromAccountId, toAccountId)) {
            throw new TransferException("Cannot transfer to the same account");
        }

        Account from = accounts.findById(fromAccountId)
                .orElseThrow(() -> new TransferException("No account with id " + fromAccountId));
        Account to = accounts.findById(toAccountId)
                .orElseThrow(() -> new TransferException("No account with id " + toAccountId));

        if (!Objects.equals(from.getCurrency(), to.getCurrency())) {
            throw new TransferException("Currency mismatch: cannot transfer "
                    + from.getCurrency() + " into " + to.getCurrency());
        }
        if (from.getBalance().compareTo(amount) < 0) {
            throw new TransferException("Insufficient funds");
        }

        from.setBalance(from.getBalance().subtract(amount));
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
