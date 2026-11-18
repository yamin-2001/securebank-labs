package com.securebank.labs.a01;

import java.util.List;
import java.util.Objects;

import com.securebank.core.LabToggles;
import com.securebank.domain.Account;
import com.securebank.domain.repo.AccountRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Account lookups.
 *
 * <p>Home of <strong>LAB 1 (A01 — Broken Access Control): IDOR</strong>.
 */
@Service
public class AccountService {

    private final AccountRepository accounts;
    private final LabToggles labs;

    public AccountService(AccountRepository accounts, LabToggles labs) {
        this.accounts = accounts;
        this.labs = labs;
    }

    /**
     * Fetch a single account by id.
     *
     * <p><strong>LAB 1 (VULNERABLE):</strong> the account is returned to
     * whoever asks, with no check that the caller owns it. Any authenticated
     * customer can read any other customer's balance and transaction history
     * by changing the id in the URL.
     *
     * <p><strong>FIX:</strong> delete the vulnerable branch below. The
     * ownership check that follows is the fix — it compares the account's
     * owner to the caller's id and refuses with 403 otherwise.
     */
    @Transactional(readOnly = true)
    public Account getAccount(Long id, Long callerUserId) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new AccountNotFoundException("No account with id " + id));

        if (labs.isEnabled("idor")) {
            // LAB 1 (VULNERABLE): no ownership check — returns any account by id.
            // FIX: delete this branch. The check below is the intended end state.
            return account;
        }

        // ---- FIX (the intended final state) ----
        if (callerUserId == null || !Objects.equals(account.getOwnerId(), callerUserId)) {
            throw new AccountForbiddenException("You do not own account " + id);
        }
        return account;
    }

    /** The accounts belonging to a user. */
    @Transactional(readOnly = true)
    public List<Account> listAccounts(Long ownerId) {
        return accounts.findByOwnerId(ownerId);
    }

    /** Every account in the system. Used by the admin endpoints. */
    @Transactional(readOnly = true)
    public List<Account> listAllAccounts() {
        return accounts.findAll();
    }

    /** Thrown when the requested account does not exist. */
    public static class AccountNotFoundException extends RuntimeException {
        public AccountNotFoundException(String message) {
            super(message);
        }
    }

    /** Thrown when the caller is not entitled to the account. */
    public static class AccountForbiddenException extends RuntimeException {
        public AccountForbiddenException(String message) {
            super(message);
        }
    }
}
