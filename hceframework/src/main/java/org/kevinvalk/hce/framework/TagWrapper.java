package org.kevinvalk.hce.framework;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import android.nfc.Tag;
import android.nfc.tech.TagTechnology;

public class TagWrapper implements TagTechnology
{

    private Method isConnected;
    private Method connect;
    private Method reconnect;
    private Method close;
    private Method getMaxTransceiveLength;
    private Method transceive;

    private Tag tag;
    private Object tagTech;

    public TagWrapper(Tag tag, String tech)
    {
        try {
            this.tag = tag;

            Class<?> cls = Class.forName(tech);
            Method get = cls.getMethod("get", Tag.class);
            tagTech = get.invoke(null, tag);

            isConnected = cls.getMethod("isConnected");
            connect = cls.getMethod("connect");
            reconnect = cls.getMethod("reconnect");
            close = cls.getMethod("close");
            getMaxTransceiveLength = cls.getMethod("getMaxTransceiveLength");
            transceive = cls.getMethod("transceive", byte[].class);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsRE(e);
        }
    }

    private void throwCauseAsRE(InvocationTargetException e)
    {
        if (e.getTargetException() != null) {
            throw new RuntimeException(e.getTargetException());
        }
        throw new RuntimeException(e);
    }

    private void throwCauseAsIOE(InvocationTargetException e) throws IOException
    {
        if (e.getTargetException() != null)
        {
            if (e.getTargetException() instanceof IOException)
            {
            	throw (IOException) e.getTargetException();
            }
            else
            {
                throw new RuntimeException(e.getTargetException());
            }
        }

        throw new RuntimeException(e);
    }

    @Override
    public boolean isConnected() {
        boolean result = false;
        try {
            return (Boolean) isConnected.invoke(tagTech);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsRE(e);
        }

        return result;
    }

    @Override
    public void connect() throws IOException {
        try {
            connect.invoke(tagTech);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsIOE(e);
        }
    }

    //    @Override @hide-n, so can't use annotation
    public void reconnect() throws IOException {
        try {
            reconnect.invoke(tagTech);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsIOE(e);
        }
    }

    @Override
    public void close() throws IOException {
        try {
            close.invoke(tagTech);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsIOE(e);
        }
    }

    public int getMaxTransceiveLength() {
        try {
            return (Integer) getMaxTransceiveLength.invoke(tagTech);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsRE(e);
        }

        return 0;
    }

    /**
     * Sends the data to the other end and blocks until it has received data
     * 
     * @param data
     * @return
     * @throws IOException
     */
    public byte[] transceive(byte[] data) throws IOException {
        try {
            return (byte[]) transceive.invoke(tagTech, data);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throwCauseAsIOE(e);
        }

        throw new IOException("transceive failed");
    }

    @Override
    public Tag getTag() {
        return tag;
    }
}
