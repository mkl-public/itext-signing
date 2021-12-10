package com.itextpdf.kernel.crypto;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.ReaderProperties;
import com.itextpdf.kernel.pdf.canvas.parser.PdfTextExtractor;

/**
 * @author mklink
 */
public class DecryptionTest {
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    public void testDemo1Encrypted() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/Demo1_encrypted_.pdf");
            PdfReader pdfReader = new PdfReader(resource);
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Demo \n"
                    + " \n"
                    + "Sue Northrop\n"
                    + "Name \n"
                    + "Elizabeth Schultz\n"
                    + " \n"
                    + "Elizabeth Schultz\n"
                    + "Signature \n"
                    + "Elizabeth Schultz (Apr 24, 2018) Sue Northrop (Apr 24, 2018)\n"
                    + " \n"
                    + "Date Apr 24, 2018\n"
                    + "Apr 24, 2018", text);
        }
    }

    @Test
    public void testCopiedPositiveP() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/copied-positive-P.pdf");
            PdfReader pdfReader = new PdfReader(resource);
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato", text);
        }
    }

    @Test
    public void testCR6InPwOwner4() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/c-r6-in-pw=owner4.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("owner4".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncryptedHelloWorldR6PwHôtel() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/encrypted_hello_world_r6-pw=hôtel.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("hôtel".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Goodbye, world!\n"
                    + "Hello, world!", text);
        }
    }

    @Test
    public void testEncryptedPositiveP() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/encrypted-positive-P.pdf");
            PdfReader pdfReader = new PdfReader(resource);
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato", text);
        }
    }

    @Test
    public void testEncXiLongPasswordQwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcv() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-long-password=qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcv.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcv".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncXiR6V5OMaster_User() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-R6,V5,O=master.pdf");
            PdfReader pdfReader = new PdfReader(resource);
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncXiR6V5OMaster_Owner() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-R6,V5,O=master.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("master".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncXiR6V5UViewOMaster_User() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-R6,V5,U=view,O=master.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("view".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncXiR6V5UViewOMaster_Owner() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-R6,V5,U=view,O=master.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("master".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testEncXiR6V5UwwwwwOwwwww() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/enc-XI-R6,V5,U=wwwww,O=wwwww.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("wwwww".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 30, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Potato 0", text);
        }
    }

    @Test
    public void testGraphEncryptedPwUser() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/graph-encrypted-pw=user.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("user".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "", text);
        }
    }

    @Test
    public void testIssue60101PwOwner() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/issue6010_1-pw=owner.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("owner".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Issue 6010", text);
        }
    }

    @Test
    public void testissue60102Pwæøå() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/issue6010_2-pw=æøå.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("æøå".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 10, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "Sample PDF Document\n"
                    + "Robert Maron\n"
                    + "´\n"
                    + "Grzegorz Grudzinski\n"
                    + "February 20, 1999", text);
        }
    }

    @Test
    public void testMuPDFAES256R6UUserOOwner_User() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/MuPDF-AES256-R6-u=user-o=owner.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("user".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "MuPDF \n"
                    + "a lightweight PDF and XPS viewer  \n"
                    + " ", text);
        }
    }

    @Test
    public void testMuPDFAES256R6UUserOOwner_Owner() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/MuPDF-AES256-R6-u=user-o=owner.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("owner".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "MuPDF \n"
                    + "a lightweight PDF and XPS viewer  \n"
                    + " ", text);
        }
    }

    @Test
    public void testPr65311PwAsdfasdf() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/pr6531_1-pw=asdfasdf.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("asdfasdf".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "", text);
        }
    }

    @Test
    public void testPr65312PwAsdfasdf() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/pr6531_2-pw=asdfasdf.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("asdfasdf".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 1, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "", text);
        }
    }

    @Test
    public void testThisIsATestPwp() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/THISISATEST_PWP.pdf");
            PdfReader pdfReader = new PdfReader(resource, new ReaderProperties().setPassword("password".getBytes()));
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 2, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertTrue("Wrong text extracted from page 1", text.startsWith("THIS IS A TEST"));
        }
    }

    @Test
    public void testRn2104812() throws IOException {
        try (
            InputStream resource = getClass().getResourceAsStream("DecryptionTest/RN 2104812.pdf");
            PdfReader pdfReader = new PdfReader(resource);
            PdfDocument pdfDocument = new PdfDocument(pdfReader);
        ) {
            assertTrue("PdfReader fails to report test file to be encrypted.", pdfReader.isEncrypted());
            assertEquals("PdfDocument fails to report the correct number of pages", 3, pdfDocument.getNumberOfPages());
            String text = PdfTextExtractor.getTextFromPage(pdfDocument.getFirstPage());
            assertEquals("Wrong text extracted from page 1", "  02/18/21  04:36 PM \n"
                    + "83921 RN 21 04812  PAGE 1 \n"
                    + "        \n"
                    + "An act to amend Section 791.03 of the Insurance Code, relating to \n"
                    + "insurance. \n"
                    + "SECURED\n"
                    + "COPY\n"
                    + "SECURED\n"
                    + "COPY\n"
                    + "SECURED\n"
                    + "COPY\n"
                    + "SECURED\n"
                    + "COPY\n"
                    + "210481283921BILLMA28\n"
                    + "  ", text);
        }
    }
}
