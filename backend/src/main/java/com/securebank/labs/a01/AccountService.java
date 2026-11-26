package com.securebank.labs.a01;

import java.util.List;
import java.util.Objects;

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

    public AccountService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    /**
     * Fetch a single account by id.
     *
     * <p><strong>LAB 1 (FIXED):</strong> the account is returned only if the
     * caller owns it. Any authenticated customer used to be able to read any
     * other customer's balance and transaction history by changing the id in
     * the URL; the ownership check below refuses that.
     */
    @Transactional(readOnly = true)
    public Account getAccount(Long id, Long callerUserId) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new AccountNotFoundException("No account with id " + id));
        if (!Objects.equals(account.getOwnerId(), callerUserId)) {
            throw new AccountForbiddenException("You don't own account with id " + id);
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
