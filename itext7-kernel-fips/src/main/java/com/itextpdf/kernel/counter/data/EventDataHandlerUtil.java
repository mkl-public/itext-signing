/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2021 iText Group NV
    Authors: Bruno Lowagie, Paulo Soares, et al.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation with the addition of the
    following permission added to Section 15 as permitted in Section 7(a):
    FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
    ITEXT GROUP. ITEXT GROUP DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
    OF THIRD PARTY RIGHTS

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses or write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA, 02110-1301 USA, or download the license from the following URL:
    http://itextpdf.com/terms-of-use/

    The interactive user interfaces in modified source and object code versions
    of this program must display Appropriate Legal Notices, as required under
    Section 5 of the GNU Affero General Public License.

    In accordance with Section 7(b) of the GNU Affero General Public License,
    a covered work must retain the producer line in every PDF that is created
    or manipulated using iText.

    You can be released from the requirements of the license by purchasing
    a commercial license. Buying such a license is mandatory as soon as you
    develop commercial activities involving the iText software without
    disclosing the source code of your own applications.
    These activities include: offering paid services to customers as an ASP,
    serving PDFs on the fly in a web application, shipping iText with a closed
    source product.

    For more information, please contact iText Software Corp. at this
    address: sales@itextpdf.com
 */
package com.itextpdf.kernel.counter.data;

import com.itextpdf.io.LogMessageConstant;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.LoggerFactory;

import java.util.Comparator;

/**
 * The util class with service methods for {@link EventDataHandler} and comparator class,
 * that can be used in {@link EventDataCacheComparatorBased}.
 */
public final class EventDataHandlerUtil {

    private static final ConcurrentHashMap<Object, Thread> shutdownHooks = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Object, Thread> scheduledTasks = new ConcurrentHashMap<>();

    private EventDataHandlerUtil() {
    }

    /**
     * Registers shutdown hook for {@link EventDataHandler} that will try to process all the events that are left.
     * It isn't guarantied that all events would be processed.
     *
     * @param dataHandler the {@link EventDataHandler} for which the hook will be registered
     * @param <T> the data signature type
     * @param <V> the data type
     */
    public static <T, V extends EventData<T>> void registerProcessAllShutdownHook(final EventDataHandler<T, V> dataHandler) {
        if (shutdownHooks.containsKey(dataHandler)) {
            // hook already registered
            return;
        }
        Thread shutdownHook = new Thread(dataHandler::tryProcessRest);
        shutdownHooks.put(dataHandler, shutdownHook);

        try {
            Runtime.getRuntime().addShutdownHook(shutdownHook);
        } catch (SecurityException security) {
            LoggerFactory.getLogger(EventDataHandlerUtil.class)
                    .error(LogMessageConstant.UNABLE_TO_REGISTER_EVENT_DATA_HANDLER_SHUTDOWN_HOOK);
            shutdownHooks.remove(dataHandler);
        } catch (Exception ignored) {
            //The other exceptions are indicating that ether hook is already registered or hooks are running,
            //so there is nothing to do here
        }
    }

    /**
     * Unregister shutdown hook for {@link EventDataHandler} registered with
     * {@link EventDataHandlerUtil#registerProcessAllShutdownHook(EventDataHandler)}.
     *
     * @param dataHandler the {@link EventDataHandler} for which the hook will be unregistered
     * @param <T> the data signature type
     * @param <V> the data type
     */
    public static <T, V extends EventData<T>> void disableShutdownHooks(final EventDataHandler<T, V> dataHandler) {
        Thread toDisable = shutdownHooks.remove(dataHandler);
        if (toDisable != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(toDisable);
            } catch (SecurityException security) {
                LoggerFactory.getLogger(EventDataHandlerUtil.class)
                        .error(LogMessageConstant.UNABLE_TO_UNREGISTER_EVENT_DATA_HANDLER_SHUTDOWN_HOOK);
            } catch (Exception ignored) {
                //The other exceptions are indicating that hooks are running,
                //so there is nothing to do here
            }
        }
    }

    /**
     * Creates thread that will try to trigger event processing with time interval from
     * specified {@link EventDataHandler}.
     *
     * @param dataHandler the {@link EventDataHandler} for which the thread will be registered
     * @param <T> the data signature type
     * @param <V> the data type
     */
    public static <T, V extends EventData<T>> void registerTimedProcessing(final EventDataHandler<T, V> dataHandler) {
        if (scheduledTasks.containsKey(dataHandler)) {
            // task already registered
            return;
        }
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(dataHandler.getWaitTime().getTime());
                    dataHandler.tryProcessNextAsync(false);
                } catch (InterruptedException e) {
                    break;
                } catch (Exception any) {
                    LoggerFactory.getLogger(EventDataHandlerUtil.class)
                            .error(LogMessageConstant.UNEXPECTED_EVENT_HANDLER_SERVICE_THREAD_EXCEPTION, any);
                    break;
                }
            }
        });
        scheduledTasks.put(dataHandler, thread);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Stop the timed processing thread registered with
     * {@link EventDataHandlerUtil#registerTimedProcessing(EventDataHandler)}.
     *
     * @param dataHandler the {@link EventDataHandler} for which the thread will be registered
     * @param <T> the data signature type
     * @param <V> the data type
     */
    public static <T, V extends EventData<T>> void disableTimedProcessing(final EventDataHandler<T, V> dataHandler) {
        Thread toDisable = scheduledTasks.remove(dataHandler);
        if (toDisable != null) {
            try {
                toDisable.interrupt();
            } catch (SecurityException security) {
                LoggerFactory.getLogger(EventDataHandlerUtil.class)
                        .error(LogMessageConstant.UNABLE_TO_INTERRUPT_THREAD);
            }
        }
    }

    /**
     * Comparator class that can be used in {@link EventDataCacheComparatorBased}.
     * If so, the cache will return {@link EventData} with bigger count first.
     *
     * @param <T> the data signature type
     * @param <V> the data type
     */
    public static class BiggerCountComparator<T, V extends EventData<T>> implements Comparator<V> {
        @Override
        public int compare(V o1, V o2) {
            return Long.compare(o2.getCount(), o1.getCount());
        }
    }
}
