package com.itextpdf.kernel.crypto;

import java.io.File;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.itextpdf.kernel.pdf.EncryptionConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.WriterProperties;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;

/**
 * @author mklink
 */
public class EncryptionTest {
    final static File RESULT_FOLDER = new File("target/test/com/itextpdf/kernel/crypto", "EncryptionTest");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    public void testEncryptNewDocumentAsInIssueAes256() throws IOException {
        String pass = "abc123";
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(pass.getBytes(), pass.getBytes(),
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_256 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentAsInIssueAes256.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentAsInIssueAes256"));
        }
    }

    @Test
    public void testEncryptNewDocumentAsInIssueAes128() throws IOException {
        String pass = "abc123";
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(pass.getBytes(), pass.getBytes(),
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_128 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentAsInIssueAes128.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentAsInIssueAes128"));
        }
    }

    @Test
    public void testEncryptNewDocumentSeparatePasswordsAes256() throws IOException {
        String passUser = "user";
        String passOwner = "owner";
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(passUser.getBytes(), passOwner.getBytes(),
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_256 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentSeparatePasswordsAes256.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentSeparatePasswordsAes256"));
        }
    }

    @Test
    public void testEncryptNewDocumentSeparatePasswordsAes128() throws IOException {
        String passUser = "user";
        String passOwner = "owner";
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(passUser.getBytes(), passOwner.getBytes(),
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_128 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentSeparatePasswordsAes128.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentSeparatePasswordsAes128"));
        }
    }

    @Test
    public void testEncryptNewDocumentDefaultAndAnonymousAes256() throws IOException {
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(null, null,
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_256 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentDefaultAndAnonymousAes256.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentDefaultAndAnonymousAes256"));
        }
    }

    @Test
    public void testEncryptNewDocumentDefaultAndAnonymousAes128() throws IOException {
        WriterProperties props = new WriterProperties()
                .setStandardEncryption(null, null,
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_128 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA);

        try (
            PdfWriter writer = new PdfWriter(new File(RESULT_FOLDER, "EncryptNewDocumentDefaultAndAnonymousAes128.pdf").getPath(), props);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
        ) {
            document.add(new Paragraph("testEncryptNewDocumentDefaultAndAnonymousAes128"));
        }
    }
}
