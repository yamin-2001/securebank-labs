package com.securebank.domain.repo;

import java.util.List;

import com.securebank.domain.Transfer;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TransferRepository extends JpaRepository<Transfer, Long> {

    List<Transfer> findByFromAccountIdOrToAccountId(Long fromAccountId, Long toAccountId);

    List<Transfer> findByToAccountId(Long toAccountId);

    List<Transfer> findByFromAccountId(Long fromAccountId);

    List<Transfer> findAllByOrderByIdDesc();
}
