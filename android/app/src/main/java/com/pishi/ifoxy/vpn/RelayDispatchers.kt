package com.pishi.ifoxy.vpn

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

object RelayDispatchers {

    private const val RELAY_THREAD_STACK_BYTES = 256L * 1024L

    private const val MAX_RELAY_THREADS = 1024

    private const val IDLE_THREAD_KEEPALIVE_SECONDS = 30L

    private val threadCounter = AtomicLong(0)

    private val threadFactory = ThreadFactory { runnable ->
        Thread(null, runnable, "foxy-relay-${threadCounter.incrementAndGet()}", RELAY_THREAD_STACK_BYTES).apply {

            isDaemon = true
            priority = Thread.NORM_PRIORITY
        }
    }

    // STB-FX-08: the pool was unbounded (Int.MAX_VALUE threads). Each relayed
    // connection parks blocking copy loops on this dispatcher, so an
    // connection burst could grow native thread stacks without limit and OOM
    // the whole VPN process. The cap matches the servers' connection budgets
    // (2 blocking directions per connection, 2 servers x 256 connections).
    private val executor = ThreadPoolExecutor(
        0,
        MAX_RELAY_THREADS,
        IDLE_THREAD_KEEPALIVE_SECONDS,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        threadFactory,
    )

    val relay: CoroutineDispatcher = executor.asCoroutineDispatcher()
}
